package rules

import (
	"fmt"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// GeofencingRule, kullanıcının belirli bir coğrafi alan içinde olup olmadığını kontrol eder.
type GeofencingRule struct {
	CenterLat float64 // İzin verilen merkezin enlemi
	CenterLon float64 // İzin verilen merkezin boylamı
	RadiusKm  float64 // İzin verilen yarıçap (Kilometre cinsinden)
	RiskScore int     // Kural ihlal edildiğinde eklenecek risk puanı
}

// NewGeofencingRule, yeni bir geofencing kuralı oluşturur.
func NewGeofencingRule(lat, lon, radius float64, score int) *GeofencingRule {
	return &GeofencingRule{
		CenterLat: lat,
		CenterLon: lon,
		RadiusKm:  radius,
		RiskScore: score,
	}
}

func (g *GeofencingRule) Name() string {
	return "Geofencing"
}

func (g *GeofencingRule) Description() string {
	return fmt.Sprintf("Konumun (%.4f, %.4f) merkezli %.1f km yarıçaplı alan içinde olduğunu doğrular.", g.CenterLat, g.CenterLon, g.RadiusKm)
}

// Validate, gelen isteğin koordinatlarını kontrol eder.
func (g *GeofencingRule) Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	// IP konumu yoksa kontrol edemeyiz
	if input.IPLatitude == 0 && input.IPLongitude == 0 {
		return 0, nil
	}

	// NOT: utils.go içindeki ortak haversine fonksiyonunu kullanıyoruz.
	// Geofencing için IP konumunu baz alıyoruz (daha güvenli).
	distance := haversine(g.CenterLat, g.CenterLon, input.IPLatitude, input.IPLongitude)

	// Eğer mesafe yarıçaptan büyükse kural ihlali vardır
	if distance > g.RadiusKm {
		return g.RiskScore, nil
	}

	return 0, nil
}