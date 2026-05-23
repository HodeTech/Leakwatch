// Package slack provides detectors for Slack secret types.
package slack

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var tokenPattern = regexp.MustCompile(`xox[bpar]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}`)

// Token detects Slack Bot and User OAuth tokens.
type Token struct{}

// ID returns the unique identifier of the Slack token detector.
func (d *Token) ID() string { return "slack-token" }

// Description returns a human-readable description of the Slack token detector.
func (d *Token) Description() string { return "Slack Bot/User Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Slack token detection.
func (d *Token) Keywords() []string { return []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-"} }

// Severity returns the default severity level for Slack token findings.
func (d *Token) Severity() finding.Severity { return finding.SeverityCritical }

// Scan scans the given data for Slack token patterns.
func (d *Token) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := tokenPattern.FindAll(data, -1)
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
	detector.Register(&Token{})
}
