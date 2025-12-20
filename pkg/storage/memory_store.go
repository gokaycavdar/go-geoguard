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
package storage

import (
	"errors"
	"net"
	"sync"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// ... (Diğer struct tanımları aynı)

// MaskIP, IP adresinin son kısmını gizler (Privacy-First)
// IPv4: 192.168.1.55 -> 192.168.1.0
// IPv6: 2001:db8::1  -> 2001:db8::
func maskIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	
	// IPv4 Maskeleme (/24 subnet - Son 8 bit gizlenir)
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.Mask(net.CIDRMask(24, 32)).String()
	}
	
	// IPv6 Maskeleme (/48 subnet)
	if ipv6 := ip.To16(); ipv6 != nil {
		return ipv6.Mask(net.CIDRMask(48, 128)).String()
	}
	return ""
}

func (m *MemoryStore) SaveRecord(record *models.LoginRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if record == nil {
		return errors.New("kayıt boş olamaz")
	}

	// 1. Orijinal veriyi bozmamak için kopyasını oluştur
	recordToSave := *record

	// 2. KRİTİK ADIM: IP Adresini Maskele
	// Silmiyoruz (""), Maskeliyoruz ("88.xxx.xxx.0")
	// Böylece hem gizlilik sağlanır hem de subnet analizi yapılabilir.
	if recordToSave.IPAddress != "" {
		recordToSave.IPAddress = maskIP(recordToSave.IPAddress)
	}

	// 3. Kaydet
	m.data[record.UserID] = &recordToSave
	return nil
}