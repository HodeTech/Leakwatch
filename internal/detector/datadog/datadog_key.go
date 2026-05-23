// Package datadog provides a Datadog API Key secret detector.
package datadog

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var datadogKeyPattern = regexp.MustCompile(`(?:DD_API_KEY|DATADOG_API_KEY|datadog_api_key)\s*[=:]\s*['"]?([a-fA-F0-9]{32})['"]?`)

// Detector detects Datadog API Keys.
type Detector struct{}

// ID returns the unique identifier of the Datadog API Key detector.
func (d *Detector) ID() string { return "datadog-api-key" }

// Description returns a human-readable description of the Datadog API Key detector.
func (d *Detector) Description() string { return "Datadog API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Datadog API Key detection.
func (d *Detector) Keywords() []string {
	return []string{"DD_API_KEY", "DATADOG_API_KEY", "datadog_api_key"}
}

// Severity returns the default severity level for Datadog API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Datadog API Key patterns.
// The 32-character hex value is extracted from submatch group 1.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := datadogKeyPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		hexKey := groups[1]

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        hexKey,
			RawV2:      fullMatch,
			Redacted:   detector.RedactBytes(hexKey),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
