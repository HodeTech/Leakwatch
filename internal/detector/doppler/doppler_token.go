// Package doppler provides a Doppler Service Token secret detector.
package doppler

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var dopplerTokenPattern = regexp.MustCompile(`dp\.st\.[a-zA-Z0-9_-]{40,}`)

// Detector detects Doppler Service Tokens.
type Detector struct{}

// ID returns the unique identifier of the Doppler token detector.
func (d *Detector) ID() string { return "doppler-token" }

// Description returns a human-readable description of the Doppler token detector.
func (d *Detector) Description() string { return "Doppler Service Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Doppler token detection.
func (d *Detector) Keywords() []string { return []string{"dp.st."} }

// Severity returns the default severity level for Doppler token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Doppler Service Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := dopplerTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		redacted := "dp.st.****" + s[len(s)-4:]
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
