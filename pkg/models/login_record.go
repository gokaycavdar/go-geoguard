package models

import "time"

type LoginRecord struct {
	UserID    string
	Timestamp time.Time
	IPAddress string
	
	// Konum Bilgileri
	IPLatitude      float64
	IPLongitude     float64
	DeviceLatitude  float64
	DeviceLongitude float64
	
	CountryCode   string
	CityGeonameID uint
	ASN           uint
	
	// Cihaz Parmak İzi
	Fingerprint     string // Ham UserAgent (geriye uyumluluk)
	FingerprintHash string // UserAgent + Language hash'i
	
	// Tarayıcı Dili
	InputLanguage string
	
	// Timezone (VPN Detection için)
	IPTimezone     string // IP'den alınan timezone (Örn: "Europe/Amsterdam")
	ClientTimezone string // Client'tan alınan timezone (Örn: "Europe/Istanbul")
}