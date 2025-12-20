package models

import "time"

// LoginRecord represents a user's login event with privacy-safe data.
//
// Privacy-by-Design (GDPR/KVKK Compliance):
//   - Raw IP addresses are NEVER stored; only masked prefixes (IPv4: /24, IPv6: /64)
//   - Precise coordinates (lat/lon) are NEVER persisted; used ephemerally at runtime only
//   - Only coarse location identifiers (CountryCode, CityGeonameID) are stored
//   - Raw UserAgent is NEVER stored; only hashed fingerprint for device tracking
//
// This record is designed to be safely persisted in any storage backend
// while maintaining full functionality for security analysis.
type LoginRecord struct {
	// UserID uniquely identifies the user (provided by the integrating application).
	UserID string

	// Timestamp records when this login event occurred.
	Timestamp time.Time

	// MaskedIPPrefix is the anonymized IP address (IPv4: /24, IPv6: /64).
	// Raw IP addresses are never stored - they exist only ephemerally during request processing.
	// Example: "192.168.1.0/24" or "2001:db8::/64"
	MaskedIPPrefix string

	// Coarse Location Identifiers (Privacy-Safe)
	// Precise coordinates are never stored - only city-level identifiers.
	CountryCode   string // ISO 3166-1 alpha-2 country code (e.g., "US", "TR")
	CityGeonameID uint   // GeoNames city identifier for city-level granularity

	// Network Information
	ASN     uint   // Autonomous System Number of the network
	OrgName string // Organization name from ASN (e.g., "Google LLC", "Amazon AWS")

	// Device Fingerprint (Privacy-Safe)
	// Raw UserAgent is NEVER stored - only the hash for device change detection.
	// This prevents tracking while still enabling security analysis.
	FingerprintHash string // SHA256 hash of UserAgent + AcceptLanguage

	// Timezone Information (for VPN/proxy detection)
	IPTimezone     string // Timezone derived from IP geolocation (e.g., "Europe/Amsterdam")
	ClientTimezone string // Timezone reported by client browser (e.g., "Europe/Istanbul")
}