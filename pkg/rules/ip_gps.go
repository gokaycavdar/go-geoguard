package rules

import (
	"fmt"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// IPGPSRule compares IP-derived location with device GPS coordinates.
//
// Use cases:
//   - Detect VPN/proxy usage (IP location differs from actual GPS location)
//   - Verify user's claimed location matches their network location
//   - Cross-check frontend GPS data with backend IP geolocation
//
// Privacy-by-Design:
//   - Implements EphemeralGeoRule interface
//   - Coordinates are passed via GeoContext (never persisted)
//   - Neither IP coordinates nor GPS coordinates are stored
//   - Only the rule result (pass/fail with score) is recorded
//
// Architecture:
//   - Engine owns GeoIP lookup; rule receives only derived coordinates
//   - GPS data is optional and provided by frontend (requires user permission)
//   - Rule is testable with mock GeoContext values
type IPGPSRule struct {
	MaxDistanceKm float64 // Maximum allowed distance between IP and GPS locations
	RiskScore     int     // Points to add when distance exceeds threshold
}

// IPGPS creates a new IP-GPS cross-check rule.
//
// Parameters:
//   - maxDist: Maximum allowed distance in kilometers (recommend 50-100 km)
//   - score: Risk points to add when triggered
func IPGPS(maxDist float64, score int) *IPGPSRule {
	return &IPGPSRule{
		MaxDistanceKm: maxDist,
		RiskScore:     score,
	}
}

func (r *IPGPSRule) Name() string {
	return "IP-GPS Crosscheck"
}

func (r *IPGPSRule) Description() string {
	return fmt.Sprintf("Checks if IP location and GPS location differ by more than %.0f km.", r.MaxDistanceKm)
}

// Validate satisfies the Rule interface.
// Returns 0 because this rule requires ephemeral coordinates via ValidateWithGeo.
func (r *IPGPSRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	return 0, nil
}

// ValidateWithGeo performs IP-GPS cross-check using ephemeral geographic context.
// Implements EphemeralGeoRule interface.
//
// The engine provides coordinates via GeoContext; this rule never accesses GeoIP directly.
func (r *IPGPSRule) ValidateWithGeo(ctx GeoContext, input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	// Skip if no GPS data provided (user didn't share location)
	if ctx.DeviceLatitude == 0 && ctx.DeviceLongitude == 0 {
		return 0, nil
	}

	// Skip if no IP location available
	if ctx.IPLatitude == 0 && ctx.IPLongitude == 0 {
		return 0, nil
	}

	// Calculate distance between IP location and device GPS
	distance := haversine(ctx.IPLatitude, ctx.IPLongitude, ctx.DeviceLatitude, ctx.DeviceLongitude)

	if distance > r.MaxDistanceKm {
		return r.RiskScore, nil
	}

	return 0, nil
}