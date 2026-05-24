// Package auth0 provides an Auth0 Management API Token secret detector.
package auth0

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var auth0TokenPattern = regexp.MustCompile(`(?:AUTH0_MANAGEMENT_TOKEN|AUTH0_API_TOKEN|auth0_token)\s*[=:]\s*['"]?([A-Za-z0-9_-]{30,})['"]?`)

// Detector detects Auth0 Management API Tokens.
type Detector struct{}

// ID returns the unique identifier of the Auth0 Management Token detector.
func (d *Detector) ID() string { return "auth0-management-token" }

// Description returns a human-readable description of the Auth0 Management Token detector.
func (d *Detector) Description() string { return "Auth0 Management API Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Auth0 Management Token detection.
func (d *Detector) Keywords() []string {
	return []string{"AUTH0_MANAGEMENT_TOKEN", "AUTH0_API_TOKEN", "auth0_token", "auth0"}
}

// Severity returns the default severity level for Auth0 Management Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Auth0 Management API Token patterns.
// The token value is extracted from submatch group 1 and redacted to first 8 chars + ****.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := auth0TokenPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		tokenValue := groups[1]

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        tokenValue,
			RawV2:      fullMatch,
			Redacted:   detector.RedactBytes(tokenValue),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
