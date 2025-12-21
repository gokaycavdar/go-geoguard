package rules

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// FingerprintRule detects device/browser changes between logins.
//
// The fingerprint is a SHA256 hash of:
//   - User-Agent string (browser/device identifier)
//   - Accept-Language header (browser language preference)
//
// Use cases:
//   - Detect account sharing across different devices
//   - Identify session hijacking attempts
//   - Track device consistency for user profiling
//
// Privacy Note:
// Only a hash is stored, not the raw User-Agent or language data.
// This provides device identification without storing identifiable strings.
type FingerprintRule struct {
	RiskScore int // Points to add when fingerprint changes
}

// Fingerprint creates a new device fingerprint rule.
func Fingerprint(score int) *FingerprintRule {
	return &FingerprintRule{RiskScore: score}
}

func (f *FingerprintRule) Name() string {
	return "Device Fingerprint Change"
}

func (f *FingerprintRule) Description() string {
	return "Detects changes in device fingerprint (UserAgent + Language hash)."
}

func (f *FingerprintRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	// First login - nothing to compare
	if last == nil {
		return 0, nil
	}

	// Compare fingerprint hashes
	if input.FingerprintHash != last.FingerprintHash {
		return f.RiskScore, nil
	}

	return 0, nil
}

// GenerateFingerprintHash creates a SHA256 hash from UserAgent and Language.
// This function should be called by the engine when creating LoginRecords.
func GenerateFingerprintHash(userAgent, language string) string {
	data := userAgent + "|" + language
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}