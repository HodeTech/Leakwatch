// Package grafana provides a Grafana API Key secret detector.
package grafana

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var grafanaKeyPattern = regexp.MustCompile(`glsa_[A-Za-z0-9_]{32,}_[a-f0-9]{8}`)

// Detector detects Grafana API Keys (service account tokens).
type Detector struct{}

// ID returns the unique identifier of the Grafana API Key detector.
func (d *Detector) ID() string { return "grafana-api-key" }

// Description returns a human-readable description of the Grafana API Key detector.
func (d *Detector) Description() string { return "Grafana API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Grafana API Key detection.
func (d *Detector) Keywords() []string { return []string{"glsa_"} }

// Severity returns the default severity level for Grafana API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan scans the given data for Grafana API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := grafanaKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "glsa_****" + string(match[len(match)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
