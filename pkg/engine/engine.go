package engine

import (
	"time"

	"github.com/gokaycavdar/go-geoguard/pkg/geoip"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
	"github.com/gokaycavdar/go-geoguard/pkg/rules"
	"github.com/gokaycavdar/go-geoguard/pkg/storage"
)

// Input represents the data provided by the integrating application for analysis.
//
// This struct correlates backend-derived data (IP, headers) with frontend-derived
// signals (GPS, timezone) to enable comprehensive security analysis.
//
// Backend-Derived (populated by your server):
//   - IPAddress: From request headers (X-Forwarded-For, CF-Connecting-IP, etc.)
//   - UserAgent: From User-Agent header
//   - AcceptLanguage: From Accept-Language header
//
// Frontend-Derived (sent by client JavaScript):
//   - Latitude, Longitude: From Geolocation API (optional, requires permission)
//   - ClientTimezone: From Intl.DateTimeFormat().resolvedOptions().timeZone
//
// Privacy Note:
//   - Raw IP exists only during request processing (ephemeral)
//   - Coordinates are used for calculation only, never persisted
//   - UserAgent is hashed before storage (raw value not persisted)
type Input struct {
	// UserID uniquely identifies the user (provided by integrating application)
	UserID string

	// IPAddress is the raw IP from the request (ephemeral - never stored)
	IPAddress string

	// Latitude/Longitude from device GPS (optional, ephemeral)
	// Used for IP-GPS cross-check only, never persisted
	Latitude  float64
	Longitude float64

	// UserAgent from HTTP header (hashed before storage)
	UserAgent string

	// AcceptLanguage from HTTP header (e.g., "en-US,en;q=0.9")
	AcceptLanguage string

	// ClientTimezone from browser (e.g., "Europe/Istanbul")
	// JavaScript: Intl.DateTimeFormat().resolvedOptions().timeZone
	ClientTimezone string
}

// GeoGuard is the main security analysis engine.
//
// Architecture Principles:
//   - Engine is rule-agnostic: no type-switching on concrete rule types
//   - Engine owns all GeoIP interactions: rules receive only derived values
//   - Privacy-safe: no raw IPs or coordinates are persisted
//   - Explainable: each rule contributes to an itemized risk score
//   - Extensible: custom rules implement Rule or EphemeralGeoRule interface
//
// The engine dynamically detects if a rule implements EphemeralGeoRule
// and passes geographic context accordingly. This allows new rules to
// be added without modifying the engine.
//
// Usage:
//
//	engine := geoguard.New(geoService, historyStore)
//	engine.AddRule(rules.Velocity(900, 80))
//	result, record, err := engine.Validate(input)
type GeoGuard struct {
	geoService   *geoip.Service
	historyStore storage.HistoryStore
	rules        []rules.Rule
}

// New creates a new GeoGuard engine with the specified dependencies.
//
// Parameters:
//   - geoService: GeoIP lookup service (required for location-based rules)
//   - store: History storage backend (required for stateful rules)
//
// The engine is the sole owner of the GeoIP service. Rules never access
// GeoIP directly; they receive derived values via GeoContext.
func New(geoService *geoip.Service, store storage.HistoryStore) *GeoGuard {
	return &GeoGuard{
		geoService:   geoService,
		historyStore: store,
		rules:        make([]rules.Rule, 0),
	}
}

// AddRule adds a security rule to the engine.
// Rules are evaluated in the order they are added.
//
// The engine automatically detects if the rule implements EphemeralGeoRule
// and handles coordinate passing appropriately.
func (g *GeoGuard) AddRule(r rules.Rule) {
	g.rules = append(g.rules, r)
}

// Validate analyzes a login attempt and returns a risk assessment.
//
// Privacy Guarantees:
//   - Raw IP address exists only ephemerally within this function
//   - Returned LoginRecord contains only masked IP prefix (never raw IP)
//   - Coordinates are used for computation only, never stored
//   - UserAgent is hashed; raw value is not persisted
//
// Architecture:
//   - Engine performs all GeoIP lookups (rules never access GeoIP directly)
//   - Engine detects EphemeralGeoRule interface via type assertion
//   - No concrete rule types are referenced (engine is rule-agnostic)
//
// Returns:
//   - RiskResult: Aggregated risk score and list of triggered rules
//   - LoginRecord: Privacy-safe record suitable for persistence
//   - error: Any error during processing
//
// The caller is responsible for:
//   - Deciding whether to block based on TotalRiskScore
//   - Saving the LoginRecord via HistoryStore (for stateful rules)
func (g *GeoGuard) Validate(input Input) (*models.RiskResult, *models.LoginRecord, error) {
	// 1. Enrich with GeoIP data (ephemeral - coordinates not stored)
	geoData, err := g.geoService.GetLocation(input.IPAddress)
	if err != nil {
		geoData = &geoip.GeoData{}
	}

	asn, orgName, err := g.geoService.GetASN(input.IPAddress)
	if err != nil {
		asn = 0
		orgName = ""
	}

	// 2. CRITICAL: Mask IP at ingestion time
	// Raw IP is discarded after this point - only prefix is stored
	maskedIP := rules.MaskIP(input.IPAddress)

	// 3. Create privacy-safe LoginRecord for persistence
	// Note: NO coordinates, NO raw UserAgent - GDPR/KVKK compliant
	currentRecord := models.LoginRecord{
		UserID:          input.UserID,
		Timestamp:       time.Now(),
		MaskedIPPrefix:  maskedIP, // Masked, not raw IP
		CountryCode:     geoData.CountryCode,
		CityGeonameID:   geoData.CityGeonameID,
		ASN:             asn,
		OrgName:         orgName,
		FingerprintHash: rules.GenerateFingerprintHash(input.UserAgent, input.AcceptLanguage),
		IPTimezone:      geoData.Timezone,
		ClientTimezone:  input.ClientTimezone,
	}

	// 4. Retrieve historical data for stateful rules
	lastRecord, err := g.historyStore.GetLastRecord(input.UserID)
	if err != nil {
		lastRecord = nil
	}

	// 5. Build ephemeral geo context for rules implementing EphemeralGeoRule
	// This context exists only during rule evaluation and is garbage collected
	geoCtx := g.buildGeoContext(geoData, input, lastRecord)

	// 6. Evaluate all rules and aggregate results
	result := &models.RiskResult{
		TotalRiskScore: 0,
		Violations:     make([]models.Violation, 0),
		IsBlocked:      false,
	}

	for _, rule := range g.rules {
		var score int
		var ruleErr error

		// Dynamic interface detection: no type-switching on concrete types
		// Rules implementing EphemeralGeoRule receive geographic context
		if geoRule, ok := rule.(rules.EphemeralGeoRule); ok {
			score, ruleErr = geoRule.ValidateWithGeo(geoCtx, currentRecord, lastRecord)
		} else {
			score, ruleErr = rule.Validate(currentRecord, lastRecord)
		}

		if ruleErr != nil {
			continue
		}

		if score > 0 {
			result.TotalRiskScore += score
			result.Violations = append(result.Violations, models.Violation{
				RuleName:  rule.Name(),
				RiskScore: score,
				Reason:    rule.Description(),
			})
		}
	}

	// geoCtx goes out of scope here - coordinates are garbage collected
	// Only privacy-safe currentRecord is returned

	return result, &currentRecord, nil
}

// buildGeoContext constructs ephemeral geographic context for rules.
// This is an internal method - rules never access GeoIP directly.
//
// The context includes:
//   - Current IP coordinates (from GeoIP lookup)
//   - Device GPS coordinates (from frontend, optional)
//   - Previous IP coordinates (from GeoIP lookup of last login)
func (g *GeoGuard) buildGeoContext(geoData *geoip.GeoData, input Input, lastRecord *models.LoginRecord) rules.GeoContext {
	ctx := rules.GeoContext{
		IPLatitude:      geoData.Latitude,
		IPLongitude:     geoData.Longitude,
		DeviceLatitude:  input.Latitude,
		DeviceLongitude: input.Longitude,
	}

	// Look up previous location coordinates if historical data exists
	// This enables VelocityRule to calculate travel speed
	if lastRecord != nil && lastRecord.MaskedIPPrefix != "" {
		prevGeoData, err := g.lookupPreviousLocation(lastRecord.MaskedIPPrefix)
		if err == nil && prevGeoData != nil {
			ctx.PreviousIPLatitude = prevGeoData.Latitude
			ctx.PreviousIPLongitude = prevGeoData.Longitude
		}
	}

	return ctx
}

// lookupPreviousLocation performs ephemeral GeoIP lookup for historical IP prefix.
// Used to provide previous coordinates to stateful rules like VelocityRule.
func (g *GeoGuard) lookupPreviousLocation(maskedIPPrefix string) (*geoip.GeoData, error) {
	if maskedIPPrefix == "" {
		return nil, nil
	}

	// Extract IP from masked prefix (e.g., "192.168.1.0/24" -> "192.168.1.0")
	ipForLookup := maskedIPPrefix
	for i := len(maskedIPPrefix) - 1; i >= 0; i-- {
		if maskedIPPrefix[i] == '/' {
			ipForLookup = maskedIPPrefix[:i]
			break
		}
	}

	return g.geoService.GetLocation(ipForLookup)
}