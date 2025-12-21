package rules

import (
	"fmt"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// VelocityRule detects impossible travel by calculating the speed required
// to move between two login locations.
//
// How it works:
//   - Compares current login location with previous login location
//   - Calculates distance using city centroids from GeoIP
//   - Divides by time elapsed to get required speed
//   - Triggers if speed exceeds threshold (e.g., 900 km/h for aircraft)
//
// Privacy-by-Design:
//   - Implements EphemeralGeoRule interface
//   - Coordinates are passed via GeoContext (never persisted)
//   - Engine performs GeoIP lookup; rule receives only derived values
//   - Only masked IP prefixes are stored; coordinates are never persisted
//
// Architecture:
//   - Rule does NOT access GeoIP services directly
//   - Engine provides previous location coordinates via GeoContext
//   - Rule is testable with mock GeoContext values
//
// Limitations:
//   - Uses city centroids, not exact locations (heuristic approach)
//   - May have false positives for VPN users switching servers
//   - Thresholds should not be overly aggressive to reduce false positives
type VelocityRule struct {
	MaxSpeedKmh float64 // Maximum allowed speed (e.g., 900 km/h for aircraft)
	RiskScore   int     // Points to add when rule triggers
}

// Velocity creates a new velocity/impossible travel detection rule.
//
// Parameters:
//   - maxSpeed: Maximum realistic travel speed in km/h (recommend 900 for aircraft)
//   - score: Risk points to add when triggered
func Velocity(maxSpeed float64, score int) *VelocityRule {
	return &VelocityRule{
		MaxSpeedKmh: maxSpeed,
		RiskScore:   score,
	}
}

func (v *VelocityRule) Name() string {
	return "Impossible Travel (Velocity Check)"
}

func (v *VelocityRule) Description() string {
	return fmt.Sprintf("Checks if travel speed between logins exceeds %.0f km/h.", v.MaxSpeedKmh)
}

// Validate satisfies the Rule interface.
// Returns 0 because this rule requires ephemeral coordinates via ValidateWithGeo.
func (v *VelocityRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	return 0, nil
}

// ValidateWithGeo performs impossible travel detection using ephemeral geographic context.
// Implements EphemeralGeoRule interface.
//
// The engine provides both current and previous coordinates via GeoContext.
// This rule never accesses GeoIP services directly.
func (v *VelocityRule) ValidateWithGeo(ctx GeoContext, input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	// First login - no historical data to compare
	if lastRecord == nil {
		return 0, nil
	}

	// Cannot calculate velocity without both locations
	if ctx.IPLatitude == 0 && ctx.IPLongitude == 0 {
		return 0, nil
	}
	if ctx.PreviousIPLatitude == 0 && ctx.PreviousIPLongitude == 0 {
		return 0, nil
	}

	// Calculate distance between city centroids (heuristic)
	distance := haversine(ctx.IPLatitude, ctx.IPLongitude, ctx.PreviousIPLatitude, ctx.PreviousIPLongitude)

	// Time elapsed in hours
	duration := input.Timestamp.Sub(lastRecord.Timestamp).Hours()

	// Handle edge case: near-simultaneous logins from different locations
	if duration <= 0 {
		if distance > 10 { // 10 km tolerance for same-time different locations
			return v.RiskScore, nil
		}
		return 0, nil
	}

	speed := distance / duration

	if speed > v.MaxSpeedKmh {
		return v.RiskScore, nil
	}

	return 0, nil
}