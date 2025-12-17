package models

// RiskResult, motorun analiz sonucunu döndürür.
// İhlal edilen kurallar ve toplam risk skoru burada tutulur[cite: 93, 110].
type RiskResult struct {
	TotalRiskScore int         // Toplam risk puanı
	Violations     []Violation // Hangi kuralların ihlal edildiği
	IsBlocked      bool        // Eşik değerin aşılıp aşılmadığı
}

// Violation, ihlal edilen tek bir kuralın detayını içerir.
type Violation struct {
	RuleName  string
	RiskScore int
	Reason    string
}