package models

import "time"

// LoginRecord, kullanıcının giriş anındaki verilerini temsil eder.
// Dokümandaki LoginRecord struct yapısına sadık kalınmıştır.
type LoginRecord struct {
	UserID        string
	Timestamp     time.Time
	IPAddress     string
	Latitude      float64
	Longitude     float64
	CountryCode   string
	CityGeonameID uint
	ASN           uint
	Fingerprint   string // Browser/OS hash [cite: 108]
}