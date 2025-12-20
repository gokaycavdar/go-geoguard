package rules

import (
	"bufio"
	"net"
	"os"
	"strings"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// OpenProxyRule detects connections from known open proxy and Tor exit nodes.
//
// This rule checks the masked IP prefix against a blacklist of known
// malicious or anonymizing IP addresses.
//
// Use cases:
//   - Detect Tor exit node usage
//   - Identify compromised residential IPs (zombie networks)
//   - Block known proxy infrastructure
//
// Privacy-by-Design:
//   - IP blacklist is stored as /24 prefixes (not individual IPs)
//   - Matching is done against masked IP prefixes
//   - No raw IP addresses are stored or compared
//
// Recommended Data Sources:
//   - IPsum: https://github.com/stamparm/ipsum (Level 3+ recommended)
//   - FireHOL: https://iplists.firehol.org/
//   - Tor Exit Nodes: https://check.torproject.org/torbulkexitlist
type OpenProxyRule struct {
	ProxyPrefixes map[string]bool // Set of masked IP prefixes (/24 or /64)
	RiskScore     int             // Points to add when prefix matches
}

// maskIPToPrefix masks an IP address to its /24 (IPv4) or /64 (IPv6) prefix.
// This ensures privacy compliance - no raw IPs are stored.
func maskIPToPrefix(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	// IPv4: Mask to /24
	if ipv4 := ip.To4(); ipv4 != nil {
		masked := ipv4.Mask(net.CIDRMask(24, 32))
		return masked.String() + "/24"
	}

	// IPv6: Mask to /64
	if ipv6 := ip.To16(); ipv6 != nil {
		masked := ipv6.Mask(net.CIDRMask(64, 128))
		return masked.String() + "/64"
	}

	return ""
}

// NewOpenProxyRule creates a rule from a list of IP addresses.
// IPs are automatically masked to /24 prefixes for privacy compliance.
func NewOpenProxyRule(proxyIPs []string, score int) *OpenProxyRule {
	prefixSet := make(map[string]bool, len(proxyIPs))
	for _, ip := range proxyIPs {
		prefix := maskIPToPrefix(ip)
		if prefix != "" {
			prefixSet[prefix] = true
		}
	}
	return &OpenProxyRule{
		ProxyPrefixes: prefixSet,
		RiskScore:     score,
	}
}

// LoadOpenProxyRule loads an IP blacklist from a file.
// IPs are automatically masked to /24 prefixes.
//
// Supported formats:
//   - One IP per line
//   - Lines starting with # are ignored (comments)
//   - IPsum format: "1.2.3.4\t5" (IP + TAB + count)
//   - CIDR notation (e.g., "1.2.3.0/24")
//
// Example:
//
//	rule, err := rules.LoadOpenProxyRule("data/ipsum_level3.txt", 40)
func LoadOpenProxyRule(filePath string, score int) (*OpenProxyRule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	prefixSet := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse IPsum format: "1.2.3.4\t5" or plain IP/CIDR
		parts := strings.Fields(line)
		if len(parts) > 0 {
			ip := parts[0]
			if strings.Contains(ip, "/") {
				// Already in CIDR format
				prefixSet[ip] = true
			} else {
				// Single IP - mask to /24 prefix
				prefix := maskIPToPrefix(ip)
				if prefix != "" {
					prefixSet[prefix] = true
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &OpenProxyRule{
		ProxyPrefixes: prefixSet,
		RiskScore:     score,
	}, nil
}

// DefaultOpenProxyRule creates a rule with example proxy IPs.
// For production, use LoadOpenProxyRule with a real blacklist.
func DefaultOpenProxyRule(score int) *OpenProxyRule {
	exampleProxies := []string{
		"185.220.101.1", "185.220.101.2", "185.220.102.1",
	}
	return NewOpenProxyRule(exampleProxies, score)
}

func (o *OpenProxyRule) Name() string {
	return "Known Proxy/Tor Detection"
}

func (o *OpenProxyRule) Description() string {
	return "Checks if IP belongs to a known proxy, VPN, or Tor exit node."
}

func (o *OpenProxyRule) Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	if input.MaskedIPPrefix == "" {
		return 0, nil
	}

	// Check if masked prefix is in the blacklist
	if o.ProxyPrefixes[input.MaskedIPPrefix] {
		return o.RiskScore, nil
	}

	return 0, nil
}

// AddIP adds an IP to the blacklist at runtime.
// The IP is automatically masked to /24 prefix.
func (o *OpenProxyRule) AddIP(ip string) {
	prefix := maskIPToPrefix(ip)
	if prefix != "" {
		o.ProxyPrefixes[prefix] = true
	}
}

// RemoveIP removes an IP's prefix from the blacklist.
func (o *OpenProxyRule) RemoveIP(ip string) {
	prefix := maskIPToPrefix(ip)
	if prefix != "" {
		delete(o.ProxyPrefixes, prefix)
	}
}

// Count returns the number of prefixes in the blacklist.
func (o *OpenProxyRule) Count() int {
	return len(o.ProxyPrefixes)
}
