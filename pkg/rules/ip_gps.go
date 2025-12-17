package rules

import (
	"fmt"
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

type IPGPSRule struct {
	MaxDistanceKm float64
	RiskScore     int
}

func NewIPGPSRule(maxDist float64, score int) *IPGPSRule {
	return &IPGPSRule{
		MaxDistanceKm: maxDist,
		RiskScore:     score,
	}
}

func (r *IPGPSRule) Name() string {
	return "IP-GPS Crosscheck"
}

func (r *IPGPSRule) Description() string {
	return fmt.Sprintf("IP lokasyonu ile GPS verisi arasında %.0f km'den fazla fark olup olmadığını kontrol eder.", r.MaxDistanceKm)
}

func (r *IPGPSRule) Validate(input models.LoginRecord, last *models.LoginRecord) (int, error) {
	// Eğer kullanıcı GPS verisi göndermediyse (0,0) kontrol yapılamaz.
	if input.DeviceLatitude == 0 && input.DeviceLongitude == 0 {
		return 0, nil
	}

	// Eğer IP konumu bulunamadıysa (0,0) kontrol yapılamaz.
	if input.IPLatitude == 0 && input.IPLongitude == 0 {
		return 0, nil
	}

	// IP konumu ile Cihaz konumu arasındaki mesafeyi ölçüyoruz.
	distance := haversine(input.IPLatitude, input.IPLongitude, input.DeviceLatitude, input.DeviceLongitude)

	if distance > r.MaxDistanceKm {
		return r.RiskScore, nil
	}

	return 0, nil
}