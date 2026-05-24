// Package sentry provides a Sentry Auth Token secret detector.
package sentry

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var sentryTokenPattern = regexp.MustCompile(`sntrys_[A-Za-z0-9_]{40,}`)

// Detector detects Sentry Auth Tokens.
type Detector struct{}

func (d *Detector) ID() string { return "sentry-token" }

func (d *Detector) Description() string { return "Sentry Auth Token" }

func (d *Detector) Keywords() []string { return []string{"sntrys_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Sentry Auth Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := sentryTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "sntrys_****" + s[len(s)-4:],
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
