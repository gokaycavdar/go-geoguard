package rules

import (
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// DataCenterRule, bilinen veri merkezi ve hosting sağlayıcılarına ait ASN'leri kontrol eder.
// Not: Bu kural residential VPN'leri (NordVPN, ExpressVPN vb.) tespit edemez,
// sadece cloud/hosting altyapısı kullanan proxy ve botları yakalar.
type DataCenterRule struct {
	BlacklistedASNs map[uint]string // ASN -> Sağlayıcı Adı (örn: 1234 -> "DigitalOcean")
	RiskScore       int
}

// NewDataCenterRule, verilen kara liste ile kuralı oluşturur.
func NewDataCenterRule(blacklist map[uint]string, score int) *DataCenterRule {
	return &DataCenterRule{
		BlacklistedASNs: blacklist,
		RiskScore:       score,
	}
}

// DefaultDataCenterRule, yaygın bilinen veri merkezlerini içeren varsayılan bir kural döner.
func DefaultDataCenterRule(score int) *DataCenterRule {
	blacklist := map[uint]string{
		// --- Global Cloud Devleri ---
		16509:  "Amazon.com (AWS)",
		14618:  "Amazon.com (AWS)",
		15169:  "Google Cloud",
		396982: "Google Cloud",
		8075:   "Microsoft Azure",
		14061:  "DigitalOcean",

		// --- Avrupa & Hosting Devleri ---
		24940: "Hetzner Online GmbH",
		16276: "OVH SAS",
		12876: "Online S.A.S. (Scaleway)",
		49981: "WorldStream",

		// --- VPN/Proxy Altyapı Sağlayıcıları ---
		20473: "Choopa, LLC (Vultr)",
		60068: "Datacamp Limited (CDN77)",
		9009:  "M247 Europe", // Ticari VPN servislerinin çoğu bunu kullanır
		20940: "Akamai Technologies",
		13335: "Cloudflare", // WARP VPN veya Proxy olabilir

		// --- Linode & Diğer ---
		63949: "Linode",
		46606: "Unified Layer",
		36352: "ColoCrossing",
	}
	return NewDataCenterRule(blacklist, score)
}

func (d *DataCenterRule) Name() string {
	return "Data Center Detection"
}

func (d *DataCenterRule) Description() string {
	return "Giriş yapılan IP adresinin bilinen bir veri merkezi veya hosting sağlayıcısına ait olup olmadığını kontrol eder."
}

func (d *DataCenterRule) Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	if input.ASN == 0 {
		return 0, nil
	}

	if _, exists := d.BlacklistedASNs[input.ASN]; exists {
		return d.RiskScore, nil
	}

	return 0, nil
}