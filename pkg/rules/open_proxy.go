package rules

import (
	"bufio"
	"os"
	"strings"

	"github.com/gokaycavdar/go-geoguard/pkg/models"
)

// OpenProxyRule, bilinen open proxy IP adreslerini kontrol eder.
// Bu kural, residential IP'lerin hacklenip proxy olarak kullanılması
// senaryosunu tespit etmek için kullanılır.
//
// Not: ASN kontrolü data center'ları tespit eder, ancak ev kullanıcısının
// hacklenmiş modemi (zombi) de proxy olarak kullanılabilir. Bu kural
// o senaryoyu kapsar.
//
// Önerilen Kaynaklar:
// - IPsum: https://github.com/stamparm/ipsum (Level 3+ önerilir)
// - FireHOL: https://iplists.firehol.org/
// - Tor Exit Nodes: https://check.torproject.org/torbulkexitlist
type OpenProxyRule struct {
	ProxyIPs  map[string]bool // IP adresleri seti
	RiskScore int
}

// NewOpenProxyRule, verilen IP listesi ile kuralı oluşturur.
func NewOpenProxyRule(proxyIPs []string, score int) *OpenProxyRule {
	ipSet := make(map[string]bool, len(proxyIPs))
	for _, ip := range proxyIPs {
		ipSet[ip] = true
	}
	return &OpenProxyRule{
		ProxyIPs:  ipSet,
		RiskScore: score,
	}
}

// LoadOpenProxyRule, dosyadan IP listesi yükleyerek kuralı oluşturur.
// Desteklenen formatlar:
// - Her satırda bir IP adresi
// - # ile başlayan satırlar yorum olarak atlanır
// - IP<TAB>count formatı (IPsum) desteklenir
//
// Örnek kullanım:
//
//	rule, err := rules.LoadOpenProxyRule("data/ipsum_level3.txt", 40)
func LoadOpenProxyRule(filePath string, score int) (*OpenProxyRule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	ipSet := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Boş satır veya yorum satırını atla
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// IPsum formatı: "1.2.3.4\t5" (IP + TAB + count)
		// FireHOL formatı: "1.2.3.4" veya "1.2.3.0/24"
		parts := strings.Fields(line)
		if len(parts) > 0 {
			ip := parts[0]
			// CIDR notasyonunu şimdilik atla (sadece tek IP destekle)
			if !strings.Contains(ip, "/") {
				ipSet[ip] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &OpenProxyRule{
		ProxyIPs:  ipSet,
		RiskScore: score,
	}, nil
}

// DefaultOpenProxyRule, örnek bir liste ile kuralı oluşturur.
// Production'da LoadOpenProxyRule kullanılması önerilir.
func DefaultOpenProxyRule(score int) *OpenProxyRule {
	exampleProxies := []string{
		"185.220.101.1", "185.220.101.2", "185.220.102.1",
	}
	return NewOpenProxyRule(exampleProxies, score)
}

func (o *OpenProxyRule) Name() string {
	return "Open Proxy Detection"
}

func (o *OpenProxyRule) Description() string {
	return "Giriş yapılan IP adresinin bilinen bir open proxy veya Tor exit node olup olmadığını kontrol eder."
}

func (o *OpenProxyRule) Validate(input models.LoginRecord, lastRecord *models.LoginRecord) (int, error) {
	if input.IPAddress == "" {
		return 0, nil
	}

	// IP listede var mı?
	if o.ProxyIPs[input.IPAddress] {
		return o.RiskScore, nil
	}

	return 0, nil
}

// AddIP, çalışma zamanında listeye yeni IP ekler.
func (o *OpenProxyRule) AddIP(ip string) {
	o.ProxyIPs[ip] = true
}

// RemoveIP, listeden IP çıkarır.
func (o *OpenProxyRule) RemoveIP(ip string) {
	delete(o.ProxyIPs, ip)
}

// Count, listedeki IP sayısını döner.
func (o *OpenProxyRule) Count() int {
	return len(o.ProxyIPs)
}
