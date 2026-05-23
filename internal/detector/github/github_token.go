// Package github provides detectors for GitHub secret types.
package github

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

// tokenPattern matches GitHub Personal Access Tokens only. The OAuth-related
// prefixes (gho/ghu/ghs/ghr) are intentionally excluded here and handled
// exclusively by the github-oauth-token detector, so that any single token is
// reported by exactly one detector (see github_oauth.go).
var tokenPattern = regexp.MustCompile(`ghp_[A-Za-z0-9_]{36,100}`)

// Token detects GitHub Personal Access Tokens.
type Token struct{}

// ID returns the unique identifier of the GitHub token detector.
func (d *Token) ID() string { return "github-token" }

// Description returns a human-readable description of the GitHub token detector.
func (d *Token) Description() string { return "GitHub Personal Access Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for GitHub token detection.
func (d *Token) Keywords() []string { return []string{"ghp_"} }

// Severity returns the default severity level for GitHub token findings.
func (d *Token) Severity() finding.Severity { return finding.SeverityCritical }

// Scan scans the given data for GitHub Personal Access Token patterns.
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
