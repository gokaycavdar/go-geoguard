package rules

import (
	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// DataCenterRule detects connections from known cloud/hosting providers.
//
// This rule checks the Autonomous System Number (ASN) of the IP address
// against a blacklist of known data center providers.
//
// Use cases:
//   - Detect bot traffic originating from cloud infrastructure
//   - Identify commercial proxy services hosted in data centers
//   - Flag requests that don't originate from residential networks
//
// Limitations:
//   - Cannot detect residential VPNs (NordVPN, ExpressVPN, etc.)
//   - Only catches cloud/hosting-based proxies and bots
//   - Some legitimate users may use cloud-based browsers or VDI
//
// Important: This is a risk signal, not definitive proof of malicious activity.
type DataCenterRule struct {
	BlacklistedASNs map[uint]string // ASN -> Provider name (e.g., 16509 -> "AWS")
	RiskScore       int             // Points to add when ASN matches blacklist
}

// DataCenter creates a rule with a custom ASN blacklist.
func DataCenter(blacklist map[uint]string, score int) *DataCenterRule {
	return &DataCenterRule{
		BlacklistedASNs: blacklist,
		RiskScore:       score,
	}
}

// DefaultDataCenterRule creates a rule with common cloud provider ASNs.
// This includes major providers like AWS, Google Cloud, Azure, etc.
func DefaultDataCenterRule(score int) *DataCenterRule {
	blacklist := map[uint]string{
		// Major Cloud Providers
		16509:  "Amazon.com (AWS)",
		14618:  "Amazon.com (AWS)",
		15169:  "Google Cloud",
		396982: "Google Cloud",
		8075:   "Microsoft Azure",
		14061:  "DigitalOcean",

		// European Hosting Providers
		24940: "Hetzner Online GmbH",
		16276: "OVH SAS",
		12876: "Online S.A.S. (Scaleway)",
		49981: "WorldStream",

		// VPN/Proxy Infrastructure Providers
		20473: "Choopa, LLC (Vultr)",
		60068: "Datacamp Limited (CDN77)",
		9009:  "M247 Europe", // Used by many commercial VPN services
		20940: "Akamai Technologies",
		13335: "Cloudflare", // May include WARP VPN users

		// Other Hosting Providers
		63949: "Linode",
		46606: "Unified Layer",
		36352: "ColoCrossing",
	}
	return DataCenter(blacklist, score)
}

func (d *DataCenterRule) Name() string {
	return "Data Center IP"
}

func (d *DataCenterRule) Description() string {
	return "Detects if IP belongs to a known cloud/hosting provider."
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