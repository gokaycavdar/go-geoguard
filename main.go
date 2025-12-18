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

// APIRequest: Postman'den gelecek JSON formatı
type APIRequest struct {
	UserID         string  `json:"user_id"`
	IPAddress      string  `json:"ip_address"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	UserAgent      string  `json:"user_agent"`
	AcceptLanguage string  `json:"accept_language"`
	Timezone       string  `json:"timezone"` // Client timezone: JS ile alınır
}

var guardEngine *engine.GeoGuard
var historyStore storage.HistoryStore

func main() {
	// 1. Servisleri Başlat
	geoService, err := geoip.NewService("data/GeoLite2-City.mmdb", "data/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Fatalf("GeoIP Hatası: %v", err)
	}
	defer geoService.Close()

	historyStore = storage.NewMemoryStore()
	guardEngine = engine.New(geoService, historyStore)

	// 2. Kuralları Yükle
	configureRules(guardEngine)

	// 3. Web Sunucusunu Başlat (Gin)
	r := gin.Default()
	r.POST("/api/v1/validate", handleValidate) // Endpoint: /api/v1/validate

	log.Println("🚀 Sunucu 8080 portunda çalışıyor...")
	r.Run(":8080")
}

func handleValidate(c *gin.Context) {
	var req APIRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Engine Input Hazırlığı
	input := engine.Input{
		UserID:         req.UserID,
		IPAddress:      req.IPAddress,
		Latitude:       req.Latitude,
		Longitude:      req.Longitude,
		UserAgent:      req.UserAgent,
		AcceptLanguage: req.AcceptLanguage,
		ClientTimezone: req.Timezone,
	}

	// Analiz
	result, record, err := guardEngine.Validate(input)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Motor hatası"})
		return
	}

	// Basit Karar Mekanizması
	isBlocked := result.TotalRiskScore >= 100
	status := "ALLOWED"
	if isBlocked {
		status = "BLOCKED"
	} else {
		// Bloklanmadıysa geçmiş veriyi kaydet (Stateful kurallar için)
		historyStore.SaveRecord(record)
	}

	// Cevap Dön
	c.JSON(http.StatusOK, gin.H{
		"user_id":     req.UserID,
		"risk_score":  result.TotalRiskScore,
		"status":      status,
		"violations":  mapViolations(result.Violations),
		"ip_country":  record.CountryCode, // Bilgi amaçlı dönüyoruz
		"ip_city_id":  record.CityGeonameID,
	})
}

// Yardımcı Fonksiyon: İhlal listesini sadece isim ve puan olarak sadeleştirir
func mapViolations(violations []models.Violation) []map[string]interface{} {
	list := make([]map[string]interface{}, 0)
	for _, v := range violations {
		list = append(list, map[string]interface{}{
			"rule":  v.RuleName,
			"score": v.RiskScore,
		})
	}
	return list
}

func configureRules(eng *engine.GeoGuard) {
	// Stateless Kurallar
	eng.AddRule(rules.NewGeofencingRule(39.9334, 32.8597, 2000.0, 50)) // Geofencing
	eng.AddRule(rules.DefaultDataCenterRule(30))                       // Data Center (ASN)

	// Open Proxy - IPsum Level 3 listesinden yükle
	if proxyRule, err := rules.LoadOpenProxyRule("data/ipsum_level3.txt", 40); err == nil {
		eng.AddRule(proxyRule)
		log.Printf("✓ Open Proxy kuralı yüklendi (%d IP)", proxyRule.Count())
	} else {
		log.Printf("⚠ Open Proxy listesi yüklenemedi: %v (varsayılan kullanılıyor)", err)
		eng.AddRule(rules.DefaultOpenProxyRule(40))
	}

	eng.AddRule(rules.NewIPGPSRule(100.0, 40))    // IP-GPS Crosscheck
	eng.AddRule(rules.NewTimezoneRule(45))        // Timezone Mismatch (VPN Detection)

	// Stateful Kurallar
	eng.AddRule(rules.NewVelocityRule(900.0, 80))  // Impossible Travel
	eng.AddRule(rules.NewFingerprintRule(35))      // Device Fingerprint
	eng.AddRule(rules.NewCountryMismatchRule(25))  // Country Change
}