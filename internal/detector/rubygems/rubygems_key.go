// Package rubygems provides a RubyGems API Key secret detector.
package rubygems

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var rubygemsKeyPattern = regexp.MustCompile(`rubygems_[a-f0-9]{48}`)

// Detector detects RubyGems API Keys.
type Detector struct{}

func (d *Detector) ID() string          { return "rubygems-api-key" }
func (d *Detector) Description() string { return "RubyGems API Key" }
func (d *Detector) Keywords() []string  { return []string{"rubygems_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for RubyGems API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := rubygemsKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		raw := string(match)
		redacted := "rubygems_****" + raw[len(raw)-4:]
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
