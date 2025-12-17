package rules

import (
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)
// ... geri kalan kod aynı ...

// VPNCheckRule, bilinen VPN/Hosting sağlayıcılarına ait ASN'leri kontrol eder.
type VPNCheckRule struct {
	BlacklistedASNs map[uint]string // ASN -> Sağlayıcı Adı (örn: 1234 -> "DigitalOcean")
	RiskScore       int
}

// NewVPNCheckRule, verilen kara liste ile kuralı oluşturur.
func NewVPNCheckRule(blacklist map[uint]string, score int) *VPNCheckRule {
	return &VPNCheckRule{
		BlacklistedASNs: blacklist,
		RiskScore:       score,
	}
}

// DefaultVPNCheckRule, yaygın bilinen veri merkezlerini içeren varsayılan bir kural döner.
// Not: Gerçek hayatta bu liste çok daha geniş olmalıdır.
func DefaultVPNCheckRule(score int) *VPNCheckRule {
	blacklist := map[uint]string{
		// Örnek Hosting/VPN ASN'leri (Temsilidir)
		14061: "DigitalOcean",
		16509: "Amazon.com",
		24940: "Hetzner Online",
		20473: "Choopa, LLC (Vultr)",
		8075:  "Microsoft Azure",
		15169: "Google Cloud",
		// Cloudflare WARP veya VPN çıkış noktaları eklenebilir
		13335: "Cloudflare",
	}
	return NewVPNCheckRule(blacklist, score)
}

func (v *VPNCheckRule) Name() string {
	return "VPN/Proxy Detection"
}

func (v *VPNCheckRule) Description() string {
	return "Giriş yapılan IP adresinin bilinen bir VPN veya Hosting sağlayıcısına ait olup olmadığını kontrol eder."
}

func (v *VPNCheckRule) Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	// LoginRecord oluşturulurken ASN bilgisi zaten GeoIP servisi tarafından doldurulmuş olmalı.
	if input.ASN == 0 {
		return 0, nil // ASN bilgisi yoksa kuralı pas geçiyoruz
	}

	// ASN kara listede var mı?
	if provider, exists := v.BlacklistedASNs[input.ASN]; exists {
		// Loglama veya detaylı hata mesajı için provider adı kullanılabilir
		// Şu an sadece risk skorunu dönüyoruz.
		_ = provider 
		return v.RiskScore, nil
	}

	return 0, nil
}