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
	Fingerprint   string
	
	// YENİ EKLENEN ALAN: Tarayıcı Dili
	InputLanguage string 
}