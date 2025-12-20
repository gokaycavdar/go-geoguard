package storage

import (
	"errors"
	"sync"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// MemoryStore is a thread-safe in-memory implementation of HistoryStore.
// Suitable for testing, development, and single-instance deployments.
//
// For production use with multiple instances, implement HistoryStore
// with a distributed backend like Redis or PostgreSQL.
//
// Privacy Note:
// This store only accepts privacy-safe records:
//   - MaskedIPPrefix (not raw IP)
//   - CountryCode, CityGeonameID (not coordinates)
//
// All privacy transformations are handled by the engine layer.
type MemoryStore struct {
	data map[string]*models.LoginRecord // Key: UserID
	mu   sync.RWMutex                   // Protects concurrent access
}

// NewMemoryStore creates a new in-memory history store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string]*models.LoginRecord),
	}
}

// GetLastRecord retrieves the most recent login record for a user.
// Returns nil, nil if no previous record exists.
func (m *MemoryStore) GetLastRecord(userID string) (*models.LoginRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if record, exists := m.data[userID]; exists {
		return record, nil
	}

	return nil, nil
}

// SaveRecord stores a new login record.
// The record is copied to prevent external mutations.
func (m *MemoryStore) SaveRecord(record *models.LoginRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if record == nil {
		return errors.New("record cannot be nil")
	}

	// Copy the record to prevent external mutations
	recordToSave := *record
	m.data[record.UserID] = &recordToSave
	return nil
}