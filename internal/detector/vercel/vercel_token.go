// Package vercel provides a Vercel API Token secret detector.
package vercel

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var vercelTokenPattern = regexp.MustCompile(`vercel_[A-Za-z0-9_-]{24,}`)

// Detector detects Vercel API Tokens.
type Detector struct{}

func (d *Detector) ID() string { return "vercel-token" }

func (d *Detector) Description() string { return "Vercel API Token" }

func (d *Detector) Keywords() []string { return []string{"vercel_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Vercel API Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := vercelTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "vercel_****" + s[len(s)-4:],
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
