package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// GeoData contains geographic information derived from an IP address.
// This data is used ephemerally during request processing and should
// not be persisted directly (only derived identifiers like CityGeonameID).
type GeoData struct {
	CountryCode   string  // ISO 3166-1 alpha-2 code (e.g., "US", "TR")
	CityName      string  // English city name from GeoNames database
	CityGeonameID uint    // GeoNames city identifier (privacy-safe to store)
	Latitude      float64 // City centroid latitude (ephemeral use only)
	Longitude     float64 // City centroid longitude (ephemeral use only)
	Timezone      string  // IANA timezone (e.g., "Europe/Istanbul")
}

// Service provides GeoIP and ASN lookup functionality using MaxMind databases.
// It wraps the MaxMind GeoIP2 reader for city and ASN lookups.
type Service struct {
	cityReader *geoip2.Reader
	asnReader  *geoip2.Reader
}

// NewService creates a new GeoIP service with the specified database files.
//
// Parameters:
//   - cityDBPath: Path to GeoLite2-City.mmdb or GeoIP2-City.mmdb
//   - asnDBPath: Path to GeoLite2-ASN.mmdb or GeoIP2-ISP.mmdb
//
// The databases can be downloaded from MaxMind:
// https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
func NewService(cityDBPath, asnDBPath string) (*Service, error) {
	cityReader, err := geoip2.Open(cityDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open city database: %v", err)
	}

	asnReader, err := geoip2.Open(asnDBPath)
	if err != nil {
		cityReader.Close()
		return nil, fmt.Errorf("failed to open ASN database: %v", err)
	}

	return &Service{
		cityReader: cityReader,
		asnReader:  asnReader,
	}, nil
}

// Close releases the database file handles.
// Should be called when the service is no longer needed.
func (s *Service) Close() {
	if s.cityReader != nil {
		s.cityReader.Close()
	}
	if s.asnReader != nil {
		s.asnReader.Close()
	}
}

// GetLocation returns geographic data for an IP address.
// The returned coordinates are city centroids (not precise user locations)
// and should only be used ephemerally for calculations.
//
// Privacy Note: Coordinates should never be persisted. Store only
// the CityGeonameID and CountryCode for privacy compliance.
func (s *Service) GetLocation(ipAddress string) (*GeoData, error) {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	record, err := s.cityReader.City(ip)
	if err != nil {
		return nil, err
	}

	return &GeoData{
		CountryCode:   record.Country.IsoCode,
		CityName:      record.City.Names["en"],
		CityGeonameID: uint(record.City.GeoNameID),
		Latitude:      record.Location.Latitude,
		Longitude:     record.Location.Longitude,
		Timezone:      record.Location.TimeZone,
	}, nil
}

// GetASN returns the Autonomous System Number and organization name for an IP.
// ASN data helps identify the network operator (ISP, cloud provider, etc.).
func (s *Service) GetASN(ipAddress string) (uint, string, error) {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return 0, "", fmt.Errorf("invalid IP address: %s", ipAddress)
	}

	record, err := s.asnReader.ASN(ip)
	if err != nil {
		return 0, "", err
	}

	return uint(record.AutonomousSystemNumber), record.AutonomousSystemOrganization, nil
}