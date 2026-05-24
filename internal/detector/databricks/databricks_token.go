// Package databricks provides a Databricks Personal Access Token secret detector.
package databricks

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var databricksTokenPattern = regexp.MustCompile(`dapi[a-f0-9]{32}(-[0-9])?`)

// Detector detects Databricks Personal Access Tokens.
type Detector struct{}

// ID returns the unique identifier of the Databricks Token detector.
func (d *Detector) ID() string { return "databricks-token" }

// Description returns a human-readable description of the Databricks Token detector.
func (d *Detector) Description() string { return "Databricks Personal Access Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Databricks Token detection.
func (d *Detector) Keywords() []string { return []string{"dapi"} }

// Severity returns the default severity level for Databricks Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Databricks Personal Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := databricksTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		last4 := s[len(s)-4:]
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "dapi****" + last4,
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
