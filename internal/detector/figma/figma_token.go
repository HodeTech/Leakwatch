// Package figma provides a Figma Personal Access Token secret detector.
package figma

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var figmaTokenPattern = regexp.MustCompile(`figd_[A-Za-z0-9_-]{40,}`)

// Detector detects Figma Personal Access Tokens.
type Detector struct{}

// ID returns the unique identifier of the Figma PAT detector.
func (d *Detector) ID() string { return "figma-pat" }

// Description returns a human-readable description of the Figma PAT detector.
func (d *Detector) Description() string { return "Figma Personal Access Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Figma PAT detection.
func (d *Detector) Keywords() []string { return []string{"figd_"} }

// Severity returns the default severity level for Figma PAT findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Figma Personal Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := figmaTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "figd_****" + string(match[len(match)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
