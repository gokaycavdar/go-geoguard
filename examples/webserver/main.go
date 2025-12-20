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

// LoginRequest: Frontend'den gelen veriler
// NOT: IP, User-Agent, Accept-Language backend tarafından otomatik alınır!
// Test modunda ip_override ile farklı IP simüle edilebilir.
type LoginRequest struct {
	UserID     string  `json:"user_id" binding:"required"`
	Latitude   float64 `json:"latitude"`  // GPS koordinatı (opsiyonel)
	Longitude  float64 `json:"longitude"` // GPS koordinatı (opsiyonel)
	Timezone   string  `json:"timezone"`  // JS: Intl.DateTimeFormat().resolvedOptions().timeZone
	IPOverride string  `json:"ip_override"` // TEST: Farklı IP simülasyonu için
}

var guardEngine *engine.GeoGuard
var historyStore storage.HistoryStore

func main() {
	// 1. GeoIP Servisini Başlat
	geoService, err := geoip.NewService("../../data/GeoLite2-City.mmdb", "../../data/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Fatalf("GeoIP Hatası: %v", err)
	}
	defer geoService.Close()

	// 2. History Store (Gerçek uygulamada Redis/PostgreSQL kullanılır)
	historyStore = storage.NewMemoryStore()

	// 3. GeoGuard Engine'i Oluştur
	guardEngine = engine.New(geoService, historyStore)

	// 4. Kuralları Yükle (Geliştirici istediğini seçer)
	configureRules(guardEngine)

	// 5. Web Sunucusu
	r := gin.Default()
	
	// Güvenlik: Proxy arkasındaysa gerçek IP'yi al
	r.SetTrustedProxies([]string{"127.0.0.1"})
	
	// Demo HTML sayfası
	r.StaticFile("/", "./index.html")
	r.StaticFile("/index.html", "./index.html")
	
	// API Endpoint
	r.POST("/api/v1/login", handleLogin)
	
	log.Println("🚀 GeoGuard Demo Sunucusu - http://localhost:8080")
	r.Run(":8080")
}

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id gerekli"})
		return
	}

	// ============================================
	// GERÇEK DÜNYA: Backend otomatik alır
	// ============================================
	ipAddress := c.ClientIP()                        // Gerçek IP
	userAgent := c.GetHeader("User-Agent")           // Tarayıcı bilgisi
	acceptLanguage := c.GetHeader("Accept-Language") // Dil tercihi

	// TEST MODE: IP override varsa kullan (sadece demo/test için!)
	if req.IPOverride != "" {
		ipAddress = req.IPOverride
		log.Printf("⚠️ TEST MODE: IP override kullanılıyor: %s", ipAddress)
	}

	// Engine Input Hazırlığı
	input := engine.Input{
		UserID:         req.UserID,
		IPAddress:      ipAddress,       // ✅ Backend'den
		Latitude:       req.Latitude,    // Frontend GPS
		Longitude:      req.Longitude,   // Frontend GPS
		UserAgent:      userAgent,       // ✅ Backend'den
		AcceptLanguage: acceptLanguage,  // ✅ Backend'den
		ClientTimezone: req.Timezone,    // Frontend JS
	}

	// Risk Analizi
	result, record, err := guardEngine.Validate(input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Analiz hatası"})
		return
	}

	// Karar: 100+ puan = BLOCKED
	isBlocked := result.TotalRiskScore >= 100
	status := "ALLOWED"
	if isBlocked {
		status = "BLOCKED"
	} else {
		// Başarılı giriş → Geçmişe kaydet (Stateful kurallar için)
		historyStore.SaveRecord(record)
	}

	// Response
	c.JSON(http.StatusOK, gin.H{
		"user_id":    req.UserID,
		"status":     status,
		"risk_score": result.TotalRiskScore,
		"violations": formatViolations(result.Violations),
		"debug": gin.H{
			"detected_ip":       ipAddress,
			"detected_country":  record.CountryCode,
			"detected_timezone": record.IPTimezone,
			"client_timezone":   record.ClientTimezone,
		},
	})
}

func formatViolations(violations []models.Violation) []gin.H {
	list := make([]gin.H, 0)
	for _, v := range violations {
		list = append(list, gin.H{
			"rule":   v.RuleName,
			"score":  v.RiskScore,
			"reason": v.Reason,
		})
	}
	return list
}

func configureRules(eng *engine.GeoGuard) {
	// =============================================
	// STATELESS KURALLAR (Geçmiş veriye ihtiyaç yok)
	// =============================================
	
	// 1. Geofencing: Türkiye merkezli, 500km yarıçap
	eng.AddRule(rules.NewGeofencingRule(39.0, 35.0, 500.0, 50))
	
	// 2. Data Center Detection: ASN tabanlı hosting tespiti
	eng.AddRule(rules.DefaultDataCenterRule(30))
	
	// 3. Open Proxy Detection: IPsum listesinden
	if proxyRule, err := rules.LoadOpenProxyRule("../../data/ipsum_level3.txt", 40); err == nil {
		eng.AddRule(proxyRule)
		log.Printf("✓ Open Proxy kuralı yüklendi (%d IP)", proxyRule.Count())
	}
	
	// 4. IP-GPS Crosscheck: 50km tolerans
	eng.AddRule(rules.NewIPGPSRule(50.0, 40))
	
	// 5. Timezone Mismatch: VPN Detection
	eng.AddRule(rules.NewTimezoneRule(45))

	// =============================================
	// STATEFUL KURALLAR (Geçmiş veri gerekli)
	// =============================================
	
	// 6. Velocity Check: Impossible Travel (max 900 km/h)
	eng.AddRule(rules.NewVelocityRule(900.0, 80))
	
	// 7. Device Fingerprint: Cihaz değişikliği
	eng.AddRule(rules.NewFingerprintRule(35))
	
	// 8. Country Change: Ülke değişikliği
	eng.AddRule(rules.NewCountryMismatchRule(25))
	
	log.Println("✓ 8 kural yüklendi (5 stateless, 3 stateful)")
}
