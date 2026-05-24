// Package circleci provides a CircleCI Personal API Token secret detector.
package circleci

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var circleciTokenPattern = regexp.MustCompile(`CCIPAT_[A-Za-z0-9_]{50,}`)

// Detector detects CircleCI Personal API Tokens.
type Detector struct{}

// ID returns the unique identifier of the CircleCI token detector.
func (d *Detector) ID() string { return "circleci-token" }

// Description returns a human-readable description of the CircleCI token detector.
func (d *Detector) Description() string { return "CircleCI Personal API Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for CircleCI token detection.
func (d *Detector) Keywords() []string { return []string{"CCIPAT_", "circleci", "CIRCLECI"} }

// Severity returns the default severity level for CircleCI token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan scans the given data for CircleCI Personal API Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := circleciTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "CCIPAT_****" + string(match[len(match)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
