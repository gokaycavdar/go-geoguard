package rules

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// FingerprintRule, cihaz parmak izi değişimini kontrol eder.
// Parmak izi: UserAgent + AcceptLanguage hash'i
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
	return "Kullanıcının cihaz parmak izinin (UserAgent + Dil) değişip değişmediğini kontrol eder."
}

func (f *FingerprintRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	if last == nil {
		return 0, nil // İlk giriş
	}

	// Hash tabanlı karşılaştırma
	if input.FingerprintHash != last.FingerprintHash {
		return f.RiskScore, nil
	}

	return 0, nil
}

// GenerateFingerprintHash, UserAgent ve Language'dan SHA256 hash üretir.
// Bu fonksiyon engine tarafından LoginRecord oluşturulurken çağrılmalı.
func GenerateFingerprintHash(userAgent, language string) string {
	data := userAgent + "|" + language
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}