package rules

import (
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// CountryMismatchRule, kullanıcının önceki girişe göre ülke değiştirip değiştirmediğini kontrol eder.
// Bu stateful bir kuraldır ve geçmiş veri gerektirir.
type CountryMismatchRule struct {
	RiskScore int
}

func NewCountryMismatchRule(score int) *CountryMismatchRule {
	return &CountryMismatchRule{RiskScore: score}
}

func (c *CountryMismatchRule) Name() string {
	return "Country Change Detection"
}

func (c *CountryMismatchRule) Description() string {
	return "Kullanıcının önceki girişe göre ülke değiştirip değiştirmediğini kontrol eder."
}

func (c *CountryMismatchRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	// İlk giriş veya geçmiş veri yoksa kontrol yapılamaz
	if last == nil {
		return 0, nil
	}

	// Ülke bilgisi eksikse kontrol yapılamaz
	if last.CountryCode == "" || input.CountryCode == "" {
		return 0, nil
	}

	// Kullanıcı farklı bir ülkeden giriş yapıyorsa risk puanı ekle
	if input.CountryCode != last.CountryCode {
		return c.RiskScore, nil
	}

	return 0, nil
}