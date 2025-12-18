package rules

import (
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// TimezoneRule, IP'den alınan timezone ile client'tan alınan timezone'u karşılaştırır.
// Bu kural VPN kullanımını tespit etmek için etkili bir yöntemdir.
//
// Çalışma Mantığı:
// - IP adresi GeoIP ile bir timezone'a map edilir (örn: Europe/Amsterdam)
// - Client tarayıcısı kendi timezone'unu gönderir (örn: Europe/Istanbul)
// - Eğer bu ikisi farklıysa, kullanıcı muhtemelen VPN kullanıyordur
//
// Client Tarafı (JavaScript):
//
//	timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
//
// Not: Bu yöntem, kullanıcıların timezone'u manuel değiştirmediği varsayımına dayanır.
type TimezoneRule struct {
	RiskScore int
}

// NewTimezoneRule, yeni bir timezone kuralı oluşturur.
func NewTimezoneRule(score int) *TimezoneRule {
	return &TimezoneRule{RiskScore: score}
}

func (t *TimezoneRule) Name() string {
	return "Timezone Mismatch (VPN Detection)"
}

func (t *TimezoneRule) Description() string {
	return "IP adresinin timezone'u ile tarayıcının timezone'unun uyuşup uyuşmadığını kontrol eder."
}

func (t *TimezoneRule) Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	// Her iki timezone da gerekli
	if input.IPTimezone == "" || input.ClientTimezone == "" {
		return 0, nil
	}

	// Timezone'lar farklıysa VPN/Proxy kullanımı şüphesi
	if input.IPTimezone != input.ClientTimezone {
		return t.RiskScore, nil
	}

	return 0, nil
}
