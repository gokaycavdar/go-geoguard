package geoip

import (
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// GeoData, bir IP adresi için bulunan coğrafi verileri tutar.
type GeoData struct {
	CountryCode   string
	CityName      string
	CityGeonameID uint
	Latitude      float64
	Longitude     float64
}

// Service, GeoIP ve ASN veritabanı işlemlerini yönetir.
type Service struct {
	cityReader *geoip2.Reader
	asnReader  *geoip2.Reader
}

// NewService, .mmdb dosya yollarını alarak servis örneğini oluşturur.
func NewService(cityDBPath, asnDBPath string) (*Service, error) {
	cityReader, err := geoip2.Open(cityDBPath)
	if err != nil {
		return nil, fmt.Errorf("city veritabanı açılamadı: %v", err)
	}

	asnReader, err := geoip2.Open(asnDBPath)
	if err != nil {
		cityReader.Close()
		return nil, fmt.Errorf("asn veritabanı açılamadı: %v", err)
	}

	return &Service{
		cityReader: cityReader,
		asnReader:  asnReader,
	}, nil
}

// Close, açılan veritabanı bağlantılarını kapatır.
func (s *Service) Close() {
	if s.cityReader != nil {
		s.cityReader.Close()
	}
	if s.asnReader != nil {
		s.asnReader.Close()
	}
}

// GetLocation, verilen IP adresi için şehir ve koordinat bilgilerini döner.
// [cite: 96, 97] IP adresinden şehir ve lokasyon bilgisini map eder.
func (s *Service) GetLocation(ipAddress string) (*GeoData, error) {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return nil, fmt.Errorf("geçersiz ip adresi: %s", ipAddress)
	}

	record, err := s.cityReader.City(ip)
	if err != nil {
		return nil, err
	}

	return &GeoData{
		CountryCode:   record.Country.IsoCode,
		CityName:      record.City.Names["en"],
		CityGeonameID: uint(record.City.GeoNameID),
		Latitude:      record.Location.Latitude,
		Longitude:     record.Location.Longitude,
	}, nil
}

// GetASN, verilen IP adresi için ASN numarasını ve organizasyon adını döner.
// [cite: 99] ASN verisi, IP adresinin sahibi olan ağ sağlayıcısını belirler.
func (s *Service) GetASN(ipAddress string) (uint, string, error) {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return 0, "", fmt.Errorf("geçersiz ip adresi: %s", ipAddress)
	}

	record, err := s.asnReader.ASN(ip)
	if err != nil {
		return 0, "", err
	}

	return uint(record.AutonomousSystemNumber), record.AutonomousSystemOrganization, nil
}