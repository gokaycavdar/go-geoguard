package engine

import (
	"time"

	"github.com/gokaycavdar/go-geoguard/pkg/geoip"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
	"github.com/gokaycavdar/go-geoguard/pkg/rules"
	"github.com/gokaycavdar/go-geoguard/pkg/storage"
)

// Input, geliştiricinin analiz için gönderdiği veridir.
type Input struct {
	UserID         string
	IPAddress      string
	Latitude       float64
	Longitude      float64
	UserAgent      string
	AcceptLanguage string // Tarayıcı Dili (Örn: "tr-TR")
	ClientTimezone string // Tarayıcı Timezone (Örn: "Europe/Istanbul") - JS: Intl.DateTimeFormat().resolvedOptions().timeZone
}

// GeoGuard, güvenlik motorunun ana yapısıdır.
type GeoGuard struct {
	geoService   *geoip.Service
	historyStore storage.HistoryStore
	rules        []rules.Rule
}

// New, yeni bir GeoGuard motoru oluşturur.
func New(geoService *geoip.Service, store storage.HistoryStore) *GeoGuard {
	return &GeoGuard{
		geoService:   geoService,
		historyStore: store,
		rules:        make([]rules.Rule, 0),
	}
}

// AddRule, motora yeni bir kural ekler.
func (g *GeoGuard) AddRule(r rules.Rule) {
	g.rules = append(g.rules, r)
}

// Validate, gelen isteği analiz eder ve risk sonucunu döner.
func (g *GeoGuard) Validate(input Input) (*models.RiskResult, *models.LoginRecord, error) {
	// 1. GeoIP ve ASN verilerini getir (Enrichment)
	geoData, err := g.geoService.GetLocation(input.IPAddress)
	if err != nil {
		geoData = &geoip.GeoData{}
	}

	asn, _, err := g.geoService.GetASN(input.IPAddress)
	if err != nil {
		asn = 0
	}

	// 2. Analiz edilecek LoginRecord nesnesini oluştur
	currentRecord := models.LoginRecord{
		UserID:          input.UserID,
		Timestamp:       time.Now(),
		IPAddress:       input.IPAddress,
		IPLatitude:      geoData.Latitude,
		IPLongitude:     geoData.Longitude,
		DeviceLatitude:  input.Latitude,
		DeviceLongitude: input.Longitude,
		CountryCode:     geoData.CountryCode,
		CityGeonameID:   geoData.CityGeonameID,
		ASN:             asn,
		Fingerprint:     input.UserAgent,
		FingerprintHash: rules.GenerateFingerprintHash(input.UserAgent, input.AcceptLanguage),
		InputLanguage:   input.AcceptLanguage,
		IPTimezone:      geoData.Timezone,
		ClientTimezone:  input.ClientTimezone,
	}

	// 3. Kullanıcının geçmiş verisini getir (Stateful kurallar için)
	lastRecord, err := g.historyStore.GetLastRecord(input.UserID)
	if err != nil {
		lastRecord = nil
	}

	// 4. Kuralları Çalıştır
	result := &models.RiskResult{
		TotalRiskScore: 0,
		Violations:     make([]models.Violation, 0),
		IsBlocked:      false,
	}

	for _, rule := range g.rules {
		score, err := rule.Validate(currentRecord, lastRecord)
		if err != nil {
			continue
		}

		if score > 0 {
			result.TotalRiskScore += score
			result.Violations = append(result.Violations, models.Violation{
				RuleName:  rule.Name(),
				RiskScore: score,
				Reason:    rule.Description(),
			})
		}
	}

	return result, &currentRecord, nil
}