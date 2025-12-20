// Package main demonstrates GeoGuard library usage with realistic security scenarios.
//
// This example shows how a backend service would integrate GeoGuard to analyze
// login attempts and make risk-based decisions. Each scenario represents a
// real-world security situation.
//
// Run with: go run main.go
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gokaycavdar/go-geoguard/pkg/engine"
	"github.com/gokaycavdar/go-geoguard/pkg/geoip"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
	"github.com/gokaycavdar/go-geoguard/pkg/rules"
	"github.com/gokaycavdar/go-geoguard/pkg/storage"
)

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║         GeoGuard - Security Scenario Demonstrations          ║")
	fmt.Println("║         Privacy-First Location-Based Risk Analysis           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Initialize GeoIP service with MaxMind databases
	geoService, err := geoip.NewService("../../data/GeoLite2-City.mmdb", "../../data/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Fatalf("Failed to initialize GeoIP service: %v", err)
	}
	defer geoService.Close()

	// Create in-memory storage (use Redis/PostgreSQL in production)
	store := storage.NewMemoryStore()

	// Initialize the security engine
	guard := engine.New(geoService, store)

	// Configure security rules with appropriate risk scores
	configureRules(guard)

	fmt.Println("✓ GeoGuard engine initialized with 8 security rules")
	fmt.Println()

	// Run all demonstration scenarios
	runScenario1_NormalLogin(guard, store)
	runScenario2_VPNUsage(guard, store)
	runScenario3_DataCenterIP(guard, store)
	runScenario4_ImpossibleTravel(guard, store)
	runScenario5_SameCityDifferentNetwork(guard, store)
	runScenario6_DeviceChange(guard, store)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    All Scenarios Complete                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}

// configureRules sets up the security rules with production-appropriate thresholds.
//
// Architecture Note:
//   - Rules no longer receive GeoIP services directly
//   - Engine provides ephemeral geo context to rules implementing EphemeralGeoRule
//   - This ensures proper separation of concerns and testability
func configureRules(guard *engine.GeoGuard) {
	// Stateless Rules (no historical data needed)
	guard.AddRule(rules.NewGeofencingRule(39.0, 35.0, 1500.0, 30))      // Allow Turkey + neighbors
	guard.AddRule(rules.DefaultDataCenterRule(35))                      // Cloud provider detection
	guard.AddRule(rules.NewIPGPSRule(100.0, 25))                        // IP-GPS distance check
	guard.AddRule(rules.NewTimezoneRule(40))                            // Timezone mismatch

	// Stateful Rules (require historical login data)
	// VelocityRule now receives coordinates from engine via GeoContext
	guard.AddRule(rules.NewVelocityRule(900.0, 80))                     // Impossible travel
	guard.AddRule(rules.NewFingerprintRule(30))                         // Device fingerprint change
	guard.AddRule(rules.NewCountryMismatchRule(20))                     // Country change

	// Load proxy blacklist if available
	if proxyRule, err := rules.LoadOpenProxyRule("../../data/ipsum_level3.txt", 45); err == nil {
		guard.AddRule(proxyRule)
	}
}

// Scenario 1: Normal user login from expected location
func runScenario1_NormalLogin(guard *engine.GeoGuard, store storage.HistoryStore) {
	printScenarioHeader("1", "Normal Login - Expected Location", 
		"User logs in from their usual location with matching timezone")

	result, record, _ := guard.Validate(engine.Input{
		UserID:         "user_normal",
		IPAddress:      "88.230.100.50",    // Turkish ISP (Turk Telekom)
		Latitude:       39.92,               // Ankara coordinates
		Longitude:      32.85,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
		AcceptLanguage: "tr-TR,tr;q=0.9,en;q=0.8",
		ClientTimezone: "Europe/Istanbul",
	})

	// Save successful login for future comparisons
	store.SaveRecord(record)
	
	printResult(result, record, "LOW RISK - Normal behavior, all signals consistent")
}

// Scenario 2: User connecting through VPN (timezone mismatch)
func runScenario2_VPNUsage(guard *engine.GeoGuard, store storage.HistoryStore) {
	printScenarioHeader("2", "VPN Usage Detection", 
		"IP shows Amsterdam but browser timezone is Istanbul")

	result, record, _ := guard.Validate(engine.Input{
		UserID:         "user_vpn",
		IPAddress:      "185.107.56.1",     // Netherlands VPN server
		Latitude:       39.92,               // User's real GPS (Ankara)
		Longitude:      32.85,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
		AcceptLanguage: "tr-TR,tr;q=0.9",
		ClientTimezone: "Europe/Istanbul",   // Real timezone differs from IP location
	})

	printResult(result, record, "MEDIUM RISK - Timezone mismatch suggests VPN/proxy usage")
}

// Scenario 3: Request from cloud infrastructure (possible bot/automation)
func runScenario3_DataCenterIP(guard *engine.GeoGuard, store storage.HistoryStore) {
	printScenarioHeader("3", "Data Center IP Detection", 
		"Request originates from AWS infrastructure")

	result, record, _ := guard.Validate(engine.Input{
		UserID:         "user_datacenter",
		IPAddress:      "52.94.76.1",        // AWS IP range
		Latitude:       0,                    // No GPS data
		Longitude:      0,
		UserAgent:      "python-requests/2.28.0",
		AcceptLanguage: "en-US",
		ClientTimezone: "",                   // No browser timezone
	})

	printResult(result, record, "MEDIUM RISK - Cloud provider IP, possible automation")
}

// Scenario 4: Impossible travel (physically impossible location change)
func runScenario4_ImpossibleTravel(guard *engine.GeoGuard, store storage.HistoryStore) {
	printScenarioHeader("4", "Impossible Travel Detection", 
		"User appears in London 5 minutes after Istanbul login")

	// First login: Istanbul
	fmt.Println("  Step 1: First login from Istanbul")
	result1, record1, _ := guard.Validate(engine.Input{
		UserID:         "user_travel",
		IPAddress:      "88.230.100.50",     // Istanbul
		Latitude:       41.0,
		Longitude:      29.0,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
		AcceptLanguage: "tr-TR",
		ClientTimezone: "Europe/Istanbul",
	})
	store.SaveRecord(record1)
	printMiniResult(result1, "Istanbul login")

	// Simulate 5 minutes passing (but record shows different timestamp)
	fmt.Println("  Step 2: Login from London (5 minutes later)")
	
	// Modify timestamp to simulate 5 minutes later
	result2, record2, _ := guard.Validate(engine.Input{
		UserID:         "user_travel",
		IPAddress:      "81.2.69.142",       // London IP
		Latitude:       51.5,
		Longitude:      -0.1,
		UserAgent:      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)",
		AcceptLanguage: "en-GB",
		ClientTimezone: "Europe/London",
	})

	printResult(result2, record2, "HIGH RISK - Physically impossible to travel Istanbul->London in 5 min")
}

// Scenario 5: Same city, different network (legitimate roaming)
func runScenario5_SameCityDifferentNetwork(guard *engine.GeoGuard, store storage.HistoryStore) {
	printScenarioHeader("5", "Same City - Network Change", 
		"User switches from home WiFi to mobile data")

	// First login: Home WiFi
	fmt.Println("  Step 1: Login from home WiFi")
	result1, record1, _ := guard.Validate(engine.Input{
		UserID:         "user_roaming",
		IPAddress:      "88.230.100.50",     // Home ISP
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		AcceptLanguage: "tr-TR",
		ClientTimezone: "Europe/Istanbul",
	})
	store.SaveRecord(record1)
	printMiniResult(result1, "Home WiFi")

	// Second login: Mobile data (same city, different ISP)
	fmt.Println("  Step 2: Login from mobile data (same city)")
	result2, record2, _ := guard.Validate(engine.Input{
		UserID:         "user_roaming",
		IPAddress:      "78.180.50.100",     // Mobile carrier (Vodafone TR)
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		AcceptLanguage: "tr-TR",
		ClientTimezone: "Europe/Istanbul",
	})

	printResult(result2, record2, "LOW RISK - Same city, consistent signals, likely legitimate")
}

// Scenario 6: Device change (same location, different fingerprint)
func runScenario6_DeviceChange(guard *engine.GeoGuard, store storage.HistoryStore) {
	printScenarioHeader("6", "Device Change Detection", 
		"User logs in from a new device")

	// First login: Original device
	fmt.Println("  Step 1: Login from original device (Windows)")
	result1, record1, _ := guard.Validate(engine.Input{
		UserID:         "user_device",
		IPAddress:      "88.230.100.50",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
		AcceptLanguage: "tr-TR",
		ClientTimezone: "Europe/Istanbul",
	})
	store.SaveRecord(record1)
	printMiniResult(result1, "Windows PC")

	// Wait a moment to get different timestamp
	time.Sleep(10 * time.Millisecond)

	// Second login: New device (same location)
	fmt.Println("  Step 2: Login from new device (MacOS)")
	result2, record2, _ := guard.Validate(engine.Input{
		UserID:         "user_device",
		IPAddress:      "88.230.100.50",     // Same IP
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
		AcceptLanguage: "tr-TR",
		ClientTimezone: "Europe/Istanbul",
	})

	printResult(result2, record2, "LOW-MEDIUM RISK - Device changed but location consistent")
}

// Helper functions for formatted output

func printScenarioHeader(num, title, description string) {
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("Scenario %s: %s\n", num, title)
	fmt.Printf("Description: %s\n", description)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func printResult(result *models.RiskResult, record *models.LoginRecord, interpretation string) {
	status := "✅ ALLOWED"
	if result.TotalRiskScore >= 100 {
		status = "❌ BLOCKED"
	} else if result.TotalRiskScore >= 50 {
		status = "⚠️  REVIEW"
	}

	fmt.Println()
	fmt.Printf("Result: %s (Risk Score: %d/100)\n", status, result.TotalRiskScore)
	
	if len(result.Violations) > 0 {
		fmt.Println("Triggered Rules:")
		for _, v := range result.Violations {
			fmt.Printf("  • %s (+%d points): %s\n", v.RuleName, v.RiskScore, v.Reason)
		}
	} else {
		fmt.Println("Triggered Rules: None")
	}

	fmt.Println()
	fmt.Println("Privacy-Safe Record (what gets stored):")
	fmt.Printf("  • Masked IP: %s (raw IP never stored)\n", record.MaskedIPPrefix)
	fmt.Printf("  • Country: %s\n", record.CountryCode)
	fmt.Printf("  • Timezone: IP=%s, Client=%s\n", record.IPTimezone, record.ClientTimezone)
	fmt.Println()
	fmt.Printf("Interpretation: %s\n", interpretation)
	fmt.Println()
}

func printMiniResult(result *models.RiskResult, label string) {
	fmt.Printf("    → %s: Score=%d, Violations=%d\n", label, result.TotalRiskScore, len(result.Violations))
}
