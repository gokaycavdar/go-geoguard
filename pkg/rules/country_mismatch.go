package rules

import (
	"strings"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// CountryMismatchRule, IP ülkesi ile tarayıcı dilinin uyuşup uyuşmadığını kontrol eder.
type CountryMismatchRule struct {
	RiskScore int
}

func NewCountryMismatchRule(score int) *CountryMismatchRule {
	return &CountryMismatchRule{RiskScore: score}
}

func (c *CountryMismatchRule) Name() string {
	return "Country/Language Mismatch"
}

func (c *CountryMismatchRule) Description() string {
	return "IP adresi ülkesi ile tarayıcı dil ayarlarının tutarsızlığını kontrol eder."
}

func (c *CountryMismatchRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	// Veri eksikse kontrol etme
	if input.CountryCode == "" || input.InputLanguage == "" {
		return 0, nil
	}
	
	// Gelen dil verisi genelde şöyledir: "tr-TR,tr;q=0.9"
	// Biz sadece ilk 2 harfi alalım: "tr"
	if len(input.InputLanguage) < 2 {
		return 0, nil
	}

	lang := strings.ToLower(input.InputLanguage[:2])           // "tr"
	country := strings.ToLower(input.CountryCode)              // GeoIP'den gelen ülke kodu (örn: "de")

	// --- SENARYO: Almanya IP'si ama Türkçe Tarayıcı ---
	// Bu durum VPN kullanımını veya "Gurbetçi" durumunu işaret edebilir.
	if country == "de" && lang == "tr" {
		// Log mesajı veya reason dönebiliriz
		return c.RiskScore, nil
	}
    
    // --- SENARYO: Rusya/Çin IP'si ama İngilizce Tarayıcı ---
    // Genelde saldırganlar varsayılan İngilizce Kali Linux/Windows kullanır.
    if (country == "ru" || country == "cn") && lang == "en" {
        return c.RiskScore, nil
    }

	return 0, nil
}