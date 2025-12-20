/*
Go-GeoGuard: Privacy-Focused Location-Based Security Rule Engine

Bu dosya kütüphanenin nasıl kullanılacağını gösteren basit bir CLI örnektir.
Gerçek web sunucu örneği için: examples/webserver/main.go

Kullanım:
	go run main.go

Daha fazla bilgi için: https://github.com/gokaycavdar/go-geoguard
*/
package main

import (
	"fmt"
	"log"

	"github.com/gokaycavdar/go-geoguard/pkg/engine"
	"github.com/gokaycavdar/go-geoguard/pkg/geoip"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
	"github.com/gokaycavdar/go-geoguard/pkg/rules"
	"github.com/gokaycavdar/go-geoguard/pkg/storage"
)

func main() {
	fmt.Println("===========================================")
	fmt.Println("  Go-GeoGuard - Location Security Engine  ")
	fmt.Println("===========================================")
	fmt.Println()

	// 1. GeoIP Servisini Başlat
	geoService, err := geoip.NewService("data/GeoLite2-City.mmdb", "data/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Fatalf("GeoIP başlatılamadı: %v", err)
	}
	defer geoService.Close()
	fmt.Println("✓ GeoIP servisi başlatıldı")

	// 2. History Store Oluştur
	store := storage.NewMemoryStore()
	fmt.Println("✓ Memory store oluşturuldu")

	// 3. Engine'i Oluştur
	guard := engine.New(geoService, store)
	fmt.Println("✓ GeoGuard engine oluşturuldu")

	// 4. Kuralları Ekle
	guard.AddRule(rules.NewGeofencingRule(39.0, 35.0, 500.0, 50))    // Türkiye
	guard.AddRule(rules.DefaultDataCenterRule(30))                   // ASN
	guard.AddRule(rules.NewIPGPSRule(50.0, 40))                      // IP-GPS
	guard.AddRule(rules.NewTimezoneRule(45))                         // Timezone
	guard.AddRule(rules.NewVelocityRule(900.0, 80))                  // Velocity
	guard.AddRule(rules.NewFingerprintRule(35))                      // Fingerprint
	guard.AddRule(rules.NewCountryMismatchRule(25))                  // Country
	
	// Open Proxy kuralı (dosyadan)
	if proxyRule, err := rules.LoadOpenProxyRule("data/ipsum_level3.txt", 40); err == nil {
		guard.AddRule(proxyRule)
		fmt.Printf("✓ Open Proxy kuralı yüklendi (%d IP)\n", proxyRule.Count())
	}
	
	fmt.Println("✓ 8 kural eklendi")
	fmt.Println()

	// 5. Test: Normal Kullanıcı (Türkiye)
	fmt.Println("--- TEST 1: Normal Kullanıcı (Türkiye) ---")
	result1, _, _ := guard.Validate(engine.Input{
		UserID:         "user_normal",
		IPAddress:      "88.230.100.50",    // Türk Telekom
		Latitude:       39.92,              // Ankara GPS
		Longitude:      32.85,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
		AcceptLanguage: "tr-TR",
		ClientTimezone: "Europe/Istanbul",
	})
	printResult(result1)

	// 6. Test: VPN Kullanıcısı (Timezone mismatch)
	fmt.Println("--- TEST 2: VPN Kullanıcısı (Amsterdam VPN) ---")
	result2, _, _ := guard.Validate(engine.Input{
		UserID:         "user_vpn",
		IPAddress:      "185.107.56.1",     // Amsterdam datacenter
		Latitude:       39.92,              // Ankara GPS (gerçek konum)
		Longitude:      32.85,
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
		AcceptLanguage: "tr-TR",
		ClientTimezone: "Europe/Istanbul",  // Gerçek timezone
	})
	printResult(result2)

	// 7. Test: Data Center IP (AWS)
	fmt.Println("--- TEST 3: AWS Data Center IP ---")
	result3, _, _ := guard.Validate(engine.Input{
		UserID:         "user_aws",
		IPAddress:      "52.94.76.1",       // AWS
		Latitude:       0,
		Longitude:      0,
		UserAgent:      "curl/7.68.0",
		AcceptLanguage: "en-US",
		ClientTimezone: "",
	})
	printResult(result3)

	// 8. Test: Impossible Travel (Stateful)
	fmt.Println("--- TEST 4: Impossible Travel ---")
	fmt.Println("İlk giriş: İstanbul")
	result4a, record4, _ := guard.Validate(engine.Input{
		UserID:         "user_travel",
		IPAddress:      "88.230.100.50",
		Latitude:       41.0,
		Longitude:      29.0,
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "tr-TR",
		ClientTimezone: "Europe/Istanbul",
	})
	store.SaveRecord(record4) // Kaydet
	printResult(result4a)

	fmt.Println("5 dakika sonra: Londra'dan giriş (imkansız!)")
	result4b, _, _ := guard.Validate(engine.Input{
		UserID:         "user_travel",
		IPAddress:      "81.2.69.142",      // Londra
		Latitude:       51.5,
		Longitude:      -0.1,
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-GB",
		ClientTimezone: "Europe/London",
	})
	printResult(result4b)

	fmt.Println("===========================================")
	fmt.Println("Demo tamamlandı!")
	fmt.Println()
	fmt.Println("Web demo için:")
	fmt.Println("  cd examples/webserver && go run main.go")
	fmt.Println("  Tarayıcıda: http://localhost:8080")
	fmt.Println("===========================================")
}

func printResult(result *models.RiskResult) {
	status := "✅ ALLOWED"
	if result.TotalRiskScore >= 100 {
		status = "❌ BLOCKED"
	}
	
	fmt.Printf("Sonuç: %s (Skor: %d)\n", status, result.TotalRiskScore)
	
	if len(result.Violations) > 0 {
		fmt.Println("İhlaller:")
		for _, v := range result.Violations {
			fmt.Printf("  - %s: +%d puan\n", v.RuleName, v.RiskScore)
		}
	}
	fmt.Println()
}

