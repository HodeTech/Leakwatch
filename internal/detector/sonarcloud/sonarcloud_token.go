// Package sonarcloud provides a SonarCloud/SonarQube Token secret detector.
package sonarcloud

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var sonarcloudTokenPattern = regexp.MustCompile(`sqp_[a-f0-9]{40}`)

// Detector detects SonarCloud/SonarQube Tokens.
type Detector struct{}

// ID returns the unique identifier of the SonarCloud token detector.
func (d *Detector) ID() string { return "sonarcloud-token" }

// Description returns a human-readable description of the SonarCloud token detector.
func (d *Detector) Description() string { return "SonarCloud/SonarQube Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for SonarCloud token detection.
func (d *Detector) Keywords() []string { return []string{"sqp_"} }

// Severity returns the default severity level for SonarCloud token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for SonarCloud/SonarQube Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := sonarcloudTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		redacted := "sqp_****" + s[len(s)-4:]
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redacted,
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
