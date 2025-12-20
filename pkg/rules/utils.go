package rules

import (
	"math"
	"net"
)

// haversine calculates the great-circle distance between two coordinates in kilometers.
// Uses the Haversine formula for accurate distance calculation on a sphere.
func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0

	dLat := (lat2 - lat1) * (math.Pi / 180.0)
	dLon := (lon2 - lon1) * (math.Pi / 180.0)

	lat1 = lat1 * (math.Pi / 180.0)
	lat2 = lat2 * (math.Pi / 180.0)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Sin(dLon/2)*math.Sin(dLon/2)*math.Cos(lat1)*math.Cos(lat2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadiusKm * c
}

// MaskIP anonymizes an IP address for GDPR/KVKK compliance.
//
// Privacy-by-Design:
//   - IPv4 addresses are masked to /24 (last 8 bits zeroed)
//   - IPv6 addresses are masked to /64 (last 64 bits zeroed)
//
// This ensures raw IP addresses are never persisted. The masked prefix
// provides enough granularity for security analysis (network-level)
// while protecting individual user privacy.
//
// Examples:
//   - "192.168.1.55" -> "192.168.1.0/24"
//   - "2001:db8::1" -> "2001:db8::/64"
func MaskIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// IPv4: Mask to /24 subnet (last 8 bits hidden)
	if ipv4 := ip.To4(); ipv4 != nil {
		masked := ipv4.Mask(net.CIDRMask(24, 32))
		return masked.String() + "/24"
	}

	// IPv6: Mask to /64 subnet (last 64 bits hidden)
	if ipv6 := ip.To16(); ipv6 != nil {
		masked := ipv6.Mask(net.CIDRMask(64, 128))
		return masked.String() + "/64"
	}

	return ""
}