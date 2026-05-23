// Package snyk provides a Snyk API Key secret detector.
package snyk

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var snykKeyPattern = regexp.MustCompile(`(?:SNYK_TOKEN|snyk_token|SNYK_API_KEY)\s*[=:]\s*['"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]?`)

// Detector detects Snyk API Keys.
type Detector struct{}

// ID returns the unique identifier of the Snyk API Key detector.
func (d *Detector) ID() string { return "snyk-api-key" }

// Description returns a human-readable description of the Snyk API Key detector.
func (d *Detector) Description() string { return "Snyk API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Snyk API Key detection.
func (d *Detector) Keywords() []string {
	return []string{"SNYK_TOKEN", "snyk_token", "SNYK_API_KEY"}
}

// Severity returns the default severity level for Snyk API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Snyk API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := snykKeyPattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match[1],
			Redacted:   detector.RedactBytes(match[1]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
