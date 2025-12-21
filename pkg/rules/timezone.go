package rules

import (
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// TimezoneRule compares IP-derived timezone with client-reported timezone.
//
// This is an effective heuristic for detecting VPN/proxy usage:
//   - IP address maps to a timezone via GeoIP (e.g., "Europe/Amsterdam")
//   - Client browser reports its local timezone (e.g., "Europe/Istanbul")
//   - Mismatch suggests the user may be masking their true location
//
// Frontend Integration (JavaScript):
//
//	timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
//
// Limitations:
//   - Assumes users haven't manually changed their system timezone
//   - Some legitimate scenarios may cause mismatches (travelers)
//   - Should be combined with other signals, not used as sole indicator
//
// Important: This rule indicates a risk factor, NOT a definitive VPN detection.
// The system does not claim deterministic VPN detection.
type TimezoneRule struct {
	RiskScore int // Points to add when timezones don't match
}

// Timezone creates a new timezone mismatch rule.
func Timezone(score int) *TimezoneRule {
	return &TimezoneRule{RiskScore: score}
}

func (t *TimezoneRule) Name() string {
	return "Timezone Mismatch"
}

func (t *TimezoneRule) Description() string {
	return "Checks if IP-derived timezone differs from client-reported timezone."
}

func (t *TimezoneRule) Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	// Both timezones required for comparison
	if input.IPTimezone == "" || input.ClientTimezone == "" {
		return 0, nil
	}

	// Mismatch indicates potential VPN/proxy usage
	if input.IPTimezone != input.ClientTimezone {
		return t.RiskScore, nil
	}

	return 0, nil
}
