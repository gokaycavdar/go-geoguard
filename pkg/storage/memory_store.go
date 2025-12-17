package storage

import (
	"errors"
	"sync"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// MemoryStore, verileri bellekte (RAM) tutan thread-safe bir yapıdır.
// Sadece test ve geliştirme amaçlıdır.
type MemoryStore struct {
	data map[string]*models.LoginRecord // Key: UserID
	mu   sync.RWMutex                   // Eşzamanlı erişim (concurrency) için kilit
}

// NewMemoryStore yeni bir bellek deposu oluşturur.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		data: make(map[string]*models.LoginRecord),
	}
}

// GetLastRecord, kullanıcının son kaydını getirir.
func (m *MemoryStore) GetLastRecord(userID string) (*models.LoginRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if record, exists := m.data[userID]; exists {
		return record, nil
	}
	
	// Kayıt yoksa nil dönebiliriz veya özel bir hata fırlatabiliriz.
	// Engine tarafında nil kontrolü yaptığımız için burada hata dönmemize gerek yok.
	return nil, nil 
}

// SaveRecord, yeni kaydı belleğe yazar.
func (m *MemoryStore) SaveRecord(record *models.LoginRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if record == nil {
		return errors.New("kayıt boş olamaz")
	}

	// Pointer'ın kopyasını saklamak daha güvenlidir ama şimdilik direkt atıyoruz.
	// Yeni gelen kayıt "son kayıt" olarak güncellenir.
	m.data[record.UserID] = record
	return nil
}