package rules

import (
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// FingerprintRule, cihaz parmak izi değişimini kontrol eder.
type FingerprintRule struct {
	RiskScore int
}

func NewFingerprintRule(score int) *FingerprintRule {
	return &FingerprintRule{RiskScore: score}
}

func (f *FingerprintRule) Name() string {
	return "Device Fingerprint Mismatch"
}

func (f *FingerprintRule) Description() string {
	return "Kullanıcının cihaz parmak izinin (User-Agent vb.) değişip değişmediğini kontrol eder."
}

func (f *FingerprintRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	if last == nil {
		return 0, nil // İlk giriş
	}

	// Basit string karşılaştırma. İleride daha kompleks hash algoritmaları eklenebilir.
	if input.Fingerprint != last.Fingerprint {
		return f.RiskScore, nil
	}

	return 0, nil
}