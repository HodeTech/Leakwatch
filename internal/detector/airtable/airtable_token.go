// Package airtable provides an Airtable Personal Access Token secret detector.
package airtable

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var airtableTokenPattern = regexp.MustCompile(`pat[A-Za-z0-9]{14}\.[a-f0-9]{64}`)

// Detector detects Airtable Personal Access Tokens.
type Detector struct{}

// ID returns the unique identifier of the Airtable PAT detector.
func (d *Detector) ID() string { return "airtable-pat" }

// Description returns a human-readable description of the Airtable PAT detector.
func (d *Detector) Description() string { return "Airtable Personal Access Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Airtable PAT detection.
func (d *Detector) Keywords() []string { return []string{"pat", "airtable", "AIRTABLE"} }

// Severity returns the default severity level for Airtable PAT findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Airtable Personal Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := airtableTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   detector.RedactBytes(match),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
