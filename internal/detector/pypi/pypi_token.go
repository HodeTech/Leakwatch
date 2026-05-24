// Package pypi provides a PyPI API Token secret detector.
package pypi

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var pypiTokenPattern = regexp.MustCompile(`pypi-[A-Za-z0-9_-]{16,}`)

// Detector detects PyPI API Tokens.
type Detector struct{}

func (d *Detector) ID() string          { return "pypi-api-token" }
func (d *Detector) Description() string { return "PyPI API Token" }
func (d *Detector) Keywords() []string  { return []string{"pypi-"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for PyPI API Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := pypiTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		raw := string(match)
		redacted := "pypi-****" + raw[len(raw)-4:]
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
