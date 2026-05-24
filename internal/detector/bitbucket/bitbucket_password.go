// Package bitbucket provides a Bitbucket App Password secret detector.
package bitbucket

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var bitbucketPasswordPattern = regexp.MustCompile(`(?:BITBUCKET_APP_PASSWORD|bitbucket_app_password|bitbucket)\s*[=:]\s*['"]?([A-Za-z0-9]{18,24})['"]?`)

// Detector detects Bitbucket App Passwords.
type Detector struct{}

// ID returns the unique identifier of the Bitbucket App Password detector.
func (d *Detector) ID() string { return "bitbucket-app-password" }

// Description returns a human-readable description of the Bitbucket App Password detector.
func (d *Detector) Description() string { return "Bitbucket App Password" }

// Keywords returns the Aho-Corasick pre-filter keywords for Bitbucket App Password detection.
func (d *Detector) Keywords() []string {
	return []string{"BITBUCKET_APP_PASSWORD", "bitbucket_app_password", "bitbucket"}
}

// Severity returns the default severity level for Bitbucket App Password findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Bitbucket App Password patterns.
// The password value is extracted from submatch group 1.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := bitbucketPasswordPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		password := groups[1]

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        password,
			RawV2:      fullMatch,
			Redacted:   detector.RedactBytes(password),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
