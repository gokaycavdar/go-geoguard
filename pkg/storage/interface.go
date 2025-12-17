package storage

import "github.com/gokaycavdar/go-geoguard/pkg/models"

// HistoryStore, stateful kurallar için geçmiş veriye erişimi soyutlar.
// Geliştirici bu interface'i kendi veritabanına (Redis, Postgres vb.) göre implemente eder.
type HistoryStore interface {
	// Belirli bir kullanıcının son başarılı giriş kaydını getirir.
	GetLastRecord(userID string) (*models.LoginRecord, error)
	
	// Yeni giriş kaydını saklar.
	SaveRecord(record *models.LoginRecord) error
}	