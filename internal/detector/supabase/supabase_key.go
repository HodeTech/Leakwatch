// Package supabase provides a Supabase Service Role Key secret detector.
package supabase

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var supabaseKeyPattern = regexp.MustCompile(`sbp_[a-f0-9]{40}`)

// Detector detects Supabase Service Role Keys.
type Detector struct{}

func (d *Detector) ID() string { return "supabase-service-key" }

func (d *Detector) Description() string { return "Supabase Service Role Key" }

func (d *Detector) Keywords() []string { return []string{"sbp_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Supabase Service Role Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := supabaseKeyPattern.FindAll(data, -1)
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
