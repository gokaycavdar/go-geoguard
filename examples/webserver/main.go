// Package main demonstrates GeoGuard integration in a web server context.
//
// This example shows how to:
//   - Initialize GeoGuard with GeoIP databases
//   - Configure security rules with appropriate risk scores
//   - Process login requests and correlate frontend/backend signals
//   - Return explainable risk assessments to clients
//
// Run with: go run main.go
// Then visit: http://localhost:8080
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gokaycavdar/go-geoguard/pkg/engine"
	"github.com/gokaycavdar/go-geoguard/pkg/geoip"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
	"github.com/gokaycavdar/go-geoguard/pkg/rules"
	"github.com/gokaycavdar/go-geoguard/pkg/storage"
)

// LoginRequest represents data sent by the frontend.
//
// Backend-derived signals (IP, User-Agent, Accept-Language) are extracted
// from HTTP headers automatically. Frontend-derived signals (GPS, timezone)
// are sent in the request body.
type LoginRequest struct {
	// UserID is required - identifies the user attempting to log in
	UserID string `json:"user_id" binding:"required"`

	// Optional GPS coordinates from device (requires user permission)
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`

	// Browser timezone from JavaScript:
	// Intl.DateTimeFormat().resolvedOptions().timeZone
	Timezone string `json:"timezone"`

	// For testing only - allows simulating different IP addresses
	// MUST be disabled in production!
	IPOverride string `json:"ip_override,omitempty"`
}

var guardEngine *engine.GeoGuard
var historyStore storage.HistoryStore

func main() {
	// 1. Initialize GeoIP service with MaxMind databases
	geoService, err := geoip.NewService(
		"../../data/GeoLite2-City.mmdb",
		"../../data/GeoLite2-ASN.mmdb",
	)
	if err != nil {
		log.Fatalf("GeoIP initialization failed: %v", err)
	}
	defer geoService.Close()

	// 2. Create history store (use Redis/PostgreSQL in production)
	historyStore = storage.NewMemoryStore()

	// 3. Initialize security engine
	guardEngine = engine.New(geoService, historyStore)

	// 4. Configure security rules
	configureRules(guardEngine)

	// 5. Setup HTTP server
	r := gin.Default()

	// Security: Trust only localhost as proxy
	r.SetTrustedProxies([]string{"127.0.0.1"})

	// Serve demo UI
	r.StaticFile("/", "./index.html")
	r.StaticFile("/index.html", "./index.html")

	// API endpoint
	r.POST("/api/v1/login", handleLogin)

	log.Println("GeoGuard Demo Server running at http://localhost:8080")
	r.Run(":8080")
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	// Extract backend-derived signals from HTTP request
	// These are authoritative and cannot be spoofed by the client
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	acceptLanguage := c.GetHeader("Accept-Language")

	// TEST MODE: Allow IP override for demonstration only
	// WARNING: Must be disabled in production!
	if req.IPOverride != "" {
		ipAddress = req.IPOverride
		log.Printf("TEST MODE: Using IP override: %s", ipAddress)
	}

	// Prepare input correlating frontend and backend signals
	input := engine.Input{
		UserID:         req.UserID,
		IPAddress:      ipAddress,       // Backend-derived (authoritative)
		Latitude:       req.Latitude,    // Frontend-derived (optional)
		Longitude:      req.Longitude,   // Frontend-derived (optional)
		UserAgent:      userAgent,       // Backend-derived (authoritative)
		AcceptLanguage: acceptLanguage,  // Backend-derived
		ClientTimezone: req.Timezone,    // Frontend-derived (from JS)
	}

	// Perform risk analysis
	result, record, err := guardEngine.Validate(input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "analysis failed"})
		return
	}

	// Determine status based on risk score thresholds
	// These thresholds should be tuned based on your risk tolerance
	status := "ALLOWED"
	if result.TotalRiskScore >= 100 {
		status = "BLOCKED"
	} else if result.TotalRiskScore >= 50 {
		status = "REVIEW"
	}

	// Save record for future stateful analysis (only if not blocked)
	if status != "BLOCKED" {
		historyStore.SaveRecord(record)
	}

	// Build response with explainable risk assessment
	c.JSON(http.StatusOK, gin.H{
		"user_id":    req.UserID,
		"status":     status,
		"risk_score": result.TotalRiskScore,
		"violations": formatViolations(result.Violations),
		"debug": gin.H{
			"masked_ip_prefix":  record.MaskedIPPrefix, // Privacy-safe, never raw IP
			"detected_country":  record.CountryCode,
			"detected_timezone": record.IPTimezone,
			"client_timezone":   record.ClientTimezone,
		},
	})
}

func formatViolations(violations []models.Violation) []gin.H {
	result := make([]gin.H, 0, len(violations))
	for _, v := range violations {
		result = append(result, gin.H{
			"rule":   v.RuleName,
			"score":  v.RiskScore,
			"reason": v.Reason,
		})
	}
	return result
}

func configureRules(eng *engine.GeoGuard) {
	// =====================================================
	// STATELESS RULES (no historical data required)
	// These rules evaluate each login attempt independently
	// =====================================================

	// 1. Geofencing: Define allowed geographic area
	//    Center: Turkey (39°N, 35°E), Radius: 500km
	//    Risk Score: 50 if login originates outside allowed area
	eng.AddRule(rules.Geofencing(39.0, 35.0, 1000.0, 60)) // 1000km radius, score increased to 60

	// 2. DataCenter Detection: Identify hosting/cloud IPs
	//    Uses ASN database to detect known hosting providers
	//    Risk Score: 30 for data center IPs
	eng.AddRule(rules.DefaultDataCenterRule(30))

	// 3. Open Proxy Detection: Known malicious IP prefixes
	//    Uses IPsum threat intelligence list
	//    Risk Score: 40 for known proxy/VPN endpoints
	if proxyRule, err := rules.LoadOpenProxyRule("../../data/ipsum_level3.txt", 40); err == nil {
		eng.AddRule(proxyRule)
		log.Printf("Loaded proxy blacklist: %d prefixes", proxyRule.Count())
	}

	// 4. IP-GPS Crosscheck: Detect location spoofing
	//    Compares IP-derived location with client-provided GPS
	//    Tolerance: 50km, Risk Score: 40 for significant mismatch
	eng.AddRule(rules.IPGPS(50.0, 100)) // Score increased to 100 - BLOCK immediately on fraud

	// 5. Timezone Mismatch: Detect VPN usage
	//    Compares IP timezone with browser JavaScript timezone
	//    Risk Score: 45 for timezone inconsistency
	eng.AddRule(rules.Timezone(55)) // Score increased to 55 - ensures REVIEW status

	// =====================================================
	// STATEFUL RULES (require historical data)
	// These rules compare current login with user's history
	// =====================================================

	// 6. Velocity Check: Detect impossible travel
	//    Flags if user "travels" faster than 900 km/h between logins
	//    Risk Score: 80 for impossible travel detection
	//    Note: VelocityRule now receives coordinates from engine via GeoContext
	eng.AddRule(rules.Velocity(900.0, 80))

	// 7. Device Fingerprint: Track device changes
	//    Monitors User-Agent + Accept-Language consistency
	//    Risk Score: 35 for new device detection
	eng.AddRule(rules.Fingerprint(35))

	// 8. Country Mismatch: Track geographic consistency
	//    Flags when user's country changes between logins
	//    Risk Score: 25 for country change (lower than velocity)
	eng.AddRule(rules.CountryMismatch(25))

	log.Println("Configured 8 security rules (5 stateless, 3 stateful)")
}