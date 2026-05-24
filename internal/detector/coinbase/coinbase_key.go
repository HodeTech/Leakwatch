// Package coinbase provides a Coinbase API Key secret detector.
package coinbase

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var coinbaseKeyPattern = regexp.MustCompile(`(?:COINBASE_API_KEY|coinbase_api_key|coinbase_api_secret)\s*[=:]\s*['"]?([A-Za-z0-9+/=]{16,64})['"]?`)

// Detector detects Coinbase API Keys.
type Detector struct{}

// ID returns the unique identifier of the Coinbase API Key detector.
func (d *Detector) ID() string { return "coinbase-api-key" }

// Description returns a human-readable description of the Coinbase API Key detector.
func (d *Detector) Description() string { return "Coinbase API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Coinbase API Key detection.
func (d *Detector) Keywords() []string {
	return []string{"COINBASE_API_KEY", "coinbase_api_key", "coinbase_api_secret"}
}

// Severity returns the default severity level for Coinbase API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Coinbase API Key patterns.
// The API key value is extracted from submatch group 1.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := coinbaseKeyPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		apiKey := groups[1]

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        apiKey,
			RawV2:      fullMatch,
			Redacted:   detector.RedactBytes(apiKey),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
