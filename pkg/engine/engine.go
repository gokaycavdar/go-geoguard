package engine

import (
	"fmt"
	"time"

	"github.com/gokaycavdar/go-geoguard/pkg/geoip"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
	"github.com/gokaycavdar/go-geoguard/pkg/rules"
	"github.com/gokaycavdar/go-geoguard/pkg/storage"
)

// Input, geliştiricinin analiz için gönderdiği veridir.
type Input struct {
	UserID    string
	IPAddress string
	Latitude  float64 // Opsiyonel: Cihazdan gelen GPS verisi
	Longitude float64 // Opsiyonel: Cihazdan gelen GPS verisi
	UserAgent string  // Browser/OS tespiti için
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
// Modülerlik ilkesi gereği geliştirici istediği kuralı ekleyebilir.
func (g *GeoGuard) AddRule(r rules.Rule) {
	g.rules = append(g.rules, r)
}

// Validate, gelen isteği analiz eder ve risk sonucunu döner.
func (g *GeoGuard) Validate(input Input) (*models.RiskResult, *models.LoginRecord, error) {
	// 1. GeoIP ve ASN verilerini getir (Enrichment)
	geoData, err := g.geoService.GetLocation(input.IPAddress)
	if err != nil {
		// IP çözülemezse bile işlem devam edebilir ancak konum verisi boş olur.
		// Gerçek bir uygulamada bu durumu loglamak gerekir.
		geoData = &geoip.GeoData{}
	}

	asn, _, err := g.geoService.GetASN(input.IPAddress)
	if err != nil {
		asn = 0
	}

	// 2. Analiz edilecek LoginRecord nesnesini oluştur
	currentRecord := models.LoginRecord{
		UserID:        input.UserID,
		Timestamp:     time.Now(),
		IPAddress:     input.IPAddress,
		Latitude:      geoData.Latitude,  // IP'den gelen konum
		Longitude:     geoData.Longitude, // IP'den gelen konum
		CountryCode:   geoData.CountryCode,
		CityGeonameID: geoData.CityGeonameID,
		ASN:           asn,
		Fingerprint:   input.UserAgent, // Basitleştirilmiş fingerprint (sonra detaylandırılabilir)
	}
	
	// Not: Input içinde GPS verisi geldiyse, bu "IP-GPS Crosscheck" kuralında ayrıca kullanılacaktır.
	// Ancak LoginRecord genellikle IP tabanlı konumu saklar.

	// 3. Kullanıcının geçmiş verisini getir (Stateful kurallar için)
	lastRecord, err := g.historyStore.GetLastRecord(input.UserID)
	if err != nil {
		// Veritabanı hatası kritik olabilir veya "ilk giriş" gibi davranılabilir.
		// Şimdilik nil kabul ediyoruz (ilk giriş).
		lastRecord = nil
	}

	// 4. Kuralları Çalıştır
	result := &models.RiskResult{
		TotalRiskScore: 0,
		Violations:     make([]models.Violation, 0),
		IsBlocked:      false,
	}

	for _, rule := range g.rules {
		// Kuralı çalıştır
		score, err := rule.Validate(currentRecord, lastRecord)
		if err != nil {
			// Kural çalışırken hata oluştu (loglanmalı)
			continue
		}

		// Eğer kural ihlali varsa (skor > 0)
		if score > 0 {
			result.TotalRiskScore += score
			result.Violations = append(result.Violations, models.Violation{
				RuleName:  rule.Name(),
				RiskScore: score,
				Reason:    rule.Description(), // Basitçe description dönüyoruz, detaylandırılabilir.
			})
		}
	}

	// Not: Bloklama mantığı (IsBlocked) geliştiricinin belirleyeceği bir eşik değere göre
	// dışarıda veya burada set edilebilir. Şimdilik skoru hesaplayıp bırakıyoruz.

	return result, &currentRecord, nil
}