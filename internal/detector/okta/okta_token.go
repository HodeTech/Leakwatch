// Package okta provides an Okta API Token secret detector.
package okta

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	oktaTokenPattern   = regexp.MustCompile(`00[A-Za-z0-9_-]{40}`)
	oktaContextPattern = regexp.MustCompile(`(?i)(?:okta|SSWS)`)
)

// Detector detects Okta API Tokens.
type Detector struct{}

// ID returns the unique identifier of the Okta API Token detector.
func (d *Detector) ID() string { return "okta-api-token" }

// Description returns a human-readable description of the Okta API Token detector.
func (d *Detector) Description() string { return "Okta API Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Okta API Token detection.
func (d *Detector) Keywords() []string { return []string{"okta", "OKTA", "SSWS"} }

// Severity returns the default severity level for Okta API Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Okta API Token patterns.
// A context keyword (okta or SSWS) must be present to avoid false positives.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	if !oktaContextPattern.Match(data) {
		return nil
	}

	matches := oktaTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		redacted := "00****" + string(match[len(match)-4:])
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   redacted,
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
