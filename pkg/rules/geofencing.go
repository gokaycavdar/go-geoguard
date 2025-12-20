package rules

import (
	"fmt"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// GeofencingRule checks if a user's location is within an allowed geographic area.
//
// Use cases:
//   - Restrict access to specific regions (e.g., corporate HQ area)
//   - Detect logins from unexpected locations
//   - Compliance with regional data access policies
//
// Privacy-by-Design:
//   - Implements EphemeralGeoRule interface
//   - Coordinates are passed via GeoContext (never persisted)
//   - Only the rule result (pass/fail with score) is recorded
//
// Architecture:
//   - Engine owns GeoIP lookup; rule receives only derived coordinates
//   - Rule is testable with mock GeoContext values
type GeofencingRule struct {
	CenterLat float64 // Latitude of the allowed area center
	CenterLon float64 // Longitude of the allowed area center
	RadiusKm  float64 // Allowed radius in kilometers
	RiskScore int     // Points to add when outside the allowed area
}

// NewGeofencingRule creates a new geofencing rule.
//
// Parameters:
//   - lat, lon: Center coordinates of the allowed area
//   - radius: Allowed radius in kilometers
//   - score: Risk points to add when user is outside the area
func NewGeofencingRule(lat, lon, radius float64, score int) *GeofencingRule {
	return &GeofencingRule{
		CenterLat: lat,
		CenterLon: lon,
		RadiusKm:  radius,
		RiskScore: score,
	}
}

func (g *GeofencingRule) Name() string {
	return "Geofencing"
}

func (g *GeofencingRule) Description() string {
	return fmt.Sprintf("Verifies location is within %.1f km of allowed area.", g.RadiusKm)
}

// Validate satisfies the Rule interface.
// Returns 0 because this rule requires ephemeral coordinates via ValidateWithGeo.
func (g *GeofencingRule) Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	return 0, nil
}

// ValidateWithGeo performs geofencing validation using ephemeral geographic context.
// Implements EphemeralGeoRule interface.
//
// The engine provides coordinates via GeoContext; this rule never accesses GeoIP directly.
func (g *GeofencingRule) ValidateWithGeo(ctx GeoContext, input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	// Cannot validate without coordinates
	if ctx.IPLatitude == 0 && ctx.IPLongitude == 0 {
		return 0, nil
	}

	// Calculate distance from allowed center using Haversine formula
	distance := haversine(g.CenterLat, g.CenterLon, ctx.IPLatitude, ctx.IPLongitude)

	// Trigger if outside the allowed radius
	if distance > g.RadiusKm {
		return g.RiskScore, nil
	}

	return 0, nil
}