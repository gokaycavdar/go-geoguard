package storage

import "github.com/gokaycavdar/go-geoguard/pkg/models"

// HistoryStore defines the interface for storing and retrieving login history.
// Implementations can use any backend: in-memory, Redis, PostgreSQL, etc.
//
// Privacy Guarantee:
// All records passed to this interface are already privacy-safe:
//   - IP addresses are masked to /24 (IPv4) or /64 (IPv6)
//   - No precise coordinates are stored
//   - Only coarse location identifiers (country, city ID) are persisted
//
// The engine handles all privacy transformations before calling these methods.
type HistoryStore interface {
	// GetLastRecord retrieves the most recent login record for a user.
	// Returns nil, nil if no previous record exists (first-time user).
	GetLastRecord(userID string) (*models.LoginRecord, error)

	// SaveRecord persists a new login record.
	// The record is already privacy-safe when passed to this method.
	SaveRecord(record *models.LoginRecord) error
}