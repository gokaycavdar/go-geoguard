package rules

import (
	"fmt"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// VelocityRule, iki oturum açma işlemi arasındaki hızı kontrol eder (Impossible Travel).
type VelocityRule struct {
	MaxSpeedKmh float64 // Örn: 900 km/h (Uçak hızı)
	RiskScore   int
}

func NewVelocityRule(maxSpeed float64, score int) *VelocityRule {
	return &VelocityRule{
		MaxSpeedKmh: maxSpeed,
		RiskScore:   score,
	}
}

func (v *VelocityRule) Name() string {
	return "Impossible Travel (Velocity Check)"
}

func (v *VelocityRule) Description() string {
	return fmt.Sprintf("İki giriş arasındaki hızın %.0f km/s sınırını aşıp aşmadığını kontrol eder.", v.MaxSpeedKmh)
}

func (v *VelocityRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	// İlk giriş ise geçmiş veri yoktur, kural çalışmaz.
	if last == nil {
		return 0, nil
	}

	// İki işlem arasındaki mesafe (km) - IP Konumlarını kullanıyoruz
	distance := haversine(input.IPLatitude, input.IPLongitude, last.IPLatitude, last.IPLongitude)

	// İki işlem arasındaki zaman farkı (saat)
	duration := input.Timestamp.Sub(last.Timestamp).Hours()

	// Eğer zaman farkı çok azsa ve mesafe varsa (örn: aynı saniyede farklı ülkeler)
	if duration <= 0 {
		if distance > 10 { // 10 km tolerans
			return v.RiskScore, nil
		}
		return 0, nil
	}

	speed := distance / duration

	if speed > v.MaxSpeedKmh {
		return v.RiskScore, nil
	}

	return 0, nil
}