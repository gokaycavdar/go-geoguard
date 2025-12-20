package rules

import "github.com/gokaycavdar/go-geoguard/pkg/models"

// Rule defines the interface that all security rules must implement.
// Rules can be either stateless (only need current request data) or
// stateful (require historical data for comparison).
//
// Design Principles:
//   - Each rule is self-contained and independently testable
//   - Rules return a risk score (0 = no risk, higher = more risk)
//   - Rules provide explainable descriptions for audit purposes
//   - Rules must not make binary decisions; they only contribute scores
//
// Extensibility:
//   - Rules requiring ephemeral geographic data should implement EphemeralGeoRule
//   - The engine detects interface support dynamically via type assertion
//   - No concrete rule types are referenced in the engine
type Rule interface {
	// Name returns the unique identifier for this rule.
	// Example: "ImpossibleTravel", "GeofencingViolation"
	Name() string

	// Description returns a human-readable explanation of what this rule checks.
	// This is used in violation reports for explainability.
	Description() string

	// Validate evaluates the rule against the current login attempt.
	//
	// Parameters:
	//   - input: The current login record being analyzed
	//   - lastRecord: The user's previous login record (nil for first login)
	//
	// Returns:
	//   - int: Risk score to add (0 if rule passes, positive if triggered)
	//   - error: Any error that occurred during validation
	//
	// Note: Stateless rules may ignore lastRecord.
	// Note: Rules implementing EphemeralGeoRule will receive geo context separately.
	Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error)
}

// GeoContext provides ephemeral geographic data to rules that require it.
// This data is computed by the engine and passed to rules implementing EphemeralGeoRule.
//
// Privacy-by-Design:
//   - This context is NEVER persisted
//   - Exists only during rule evaluation (function scope)
//   - Coordinates are derived from GeoIP lookup at runtime
//   - Garbage collected immediately after rule evaluation
//
// The engine is the sole owner of GeoIP services. Rules receive only
// derived values through this context, ensuring separation of concerns.
type GeoContext struct {
	// IPLatitude and IPLongitude are city centroid coordinates from GeoIP.
	// These are approximate values (city-level precision).
	IPLatitude  float64
	IPLongitude float64

	// DeviceLatitude and DeviceLongitude are GPS coordinates from the client device.
	// These are optional and require user permission to obtain.
	// Zero values indicate GPS data was not provided.
	DeviceLatitude  float64
	DeviceLongitude float64

	// PreviousIPLatitude and PreviousIPLongitude are coordinates from the last login.
	// Used by stateful rules like VelocityRule to detect impossible travel.
	// Zero values indicate no previous login exists.
	PreviousIPLatitude  float64
	PreviousIPLongitude float64
}

// EphemeralGeoRule is an optional interface for rules that require geographic coordinates.
//
// Why this interface exists:
//   - Privacy: Coordinates must be ephemeral (never persisted)
//   - Separation of concerns: Rules should not access GeoIP services directly
//   - Testability: Rules can be tested with mock GeoContext values
//   - Extensibility: Engine detects this interface dynamically, no type-switching on concrete types
//
// Rules implementing this interface:
//   - GeofencingRule: Checks if user is within allowed geographic area
//   - IPGPSRule: Cross-checks IP location with device GPS
//   - VelocityRule: Detects impossible travel between login locations
//
// Implementation pattern:
//   - Implement both Rule.Validate() and EphemeralGeoRule.ValidateWithGeo()
//   - Rule.Validate() should return 0 (engine will call ValidateWithGeo instead)
//   - ValidateWithGeo() receives coordinates from engine, performs analysis
type EphemeralGeoRule interface {
	Rule

	// ValidateWithGeo performs rule evaluation using ephemeral geographic context.
	// The engine calls this method instead of Validate() when the rule implements
	// this interface.
	//
	// Parameters:
	//   - ctx: Ephemeral geographic context (coordinates, never persisted)
	//   - input: Current login record (privacy-safe, no coordinates)
	//   - lastRecord: Previous login record (nil for first login)
	//
	// Returns:
	//   - int: Risk score to add (0 if rule passes, positive if triggered)
	//   - error: Any error during validation
	ValidateWithGeo(ctx GeoContext, input models.LoginRecord, lastRecord *models.LoginRecord) (int, error)
}