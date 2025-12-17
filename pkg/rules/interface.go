package rules

import "github.com/gokaycavdar/go-geoguard/pkg/models"

// Rule, hem stateless (durumsuz) hem stateful (durumlu) kuralların
// uyması gereken temel arayüzdür.
type Rule interface {
	// Kuralın benzersiz adı (örn: "Geofencing", "ImpossibleTravel")
	Name() string
	
	// Kuralın ne yaptığını açıklayan kısa metin
	Description() string
	
	// Validate, kuralı çalıştırır.
	// input: Şu anki giriş denemesi.
	// lastRecord: Kullanıcının son başarılı girişi (Stateless kurallar için nil olabilir).
	// Dönüş: Risk skoru ve hata durumu.
	Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error)
}