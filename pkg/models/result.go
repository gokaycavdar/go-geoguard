package models

// RiskResult contains the complete output of a security analysis.
// It aggregates scores from all evaluated rules and provides an explainable result.
//
// The library does NOT make binary "VPN detected" or "blocked" decisions.
// Instead, it returns a risk score and detailed violations, allowing the
// integrating application to make policy decisions based on its own thresholds.
type RiskResult struct {
	// TotalRiskScore is the sum of all triggered rule scores.
	// Higher scores indicate higher risk. Typical thresholds:
	//   - 0-50: Low risk (normal behavior)
	//   - 50-100: Medium risk (some anomalies detected)
	//   - 100+: High risk (multiple security indicators)
	TotalRiskScore int

	// Violations contains details of each rule that contributed to the score.
	// This enables explainable security decisions and audit trails.
	Violations []Violation

	// IsBlocked is a convenience field that can be set by the engine
	// based on a configured threshold. Default threshold is typically 100.
	IsBlocked bool
}

// Violation represents a single rule that was triggered during analysis.
// Each violation is self-explanatory and can be logged for audit purposes.
type Violation struct {
	// RuleName is the unique identifier of the triggered rule.
	RuleName string

	// RiskScore is the points added by this specific rule.
	RiskScore int

	// Reason provides a human-readable explanation of why this rule triggered.
	Reason string
}