package rules

import (
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// CountryMismatchRule detects when a user logs in from a different country.
//
// This is a stateful rule that requires historical login data.
// It compares the current login country with the previous login country.
//
// Use cases:
//   - Detect account compromise (attacker in different country)
//   - Monitor travel patterns for anomaly detection
//   - Geographic access policy enforcement
//
// Note: Country changes may be legitimate (travel, VPN for work).
// This rule should contribute to a risk score, not block outright.
type CountryMismatchRule struct {
	RiskScore int // Points to add when country differs from previous login
}

// NewCountryMismatchRule creates a new country change detection rule.
func NewCountryMismatchRule(score int) *CountryMismatchRule {
	return &CountryMismatchRule{RiskScore: score}
}

func (c *CountryMismatchRule) Name() string {
	return "Country Change"
}

func (c *CountryMismatchRule) Description() string {
	return "Detects when login country differs from previous login."
}

func (c *CountryMismatchRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	// First login or no historical data
	if last == nil {
		return 0, nil
	}

	// Cannot compare if country data is missing
	if last.CountryCode == "" || input.CountryCode == "" {
		return 0, nil
	}

	// Country changed since last login
	if input.CountryCode != last.CountryCode {
		return c.RiskScore, nil
	}

	return 0, nil
}