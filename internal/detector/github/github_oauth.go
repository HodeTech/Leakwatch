package github

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var oauthTokenPattern = regexp.MustCompile(`gh[orus]_[A-Za-z0-9_]{36,}`)

// OAuthDetector detects GitHub OAuth2 Tokens.
type OAuthDetector struct{}

// ID returns the unique identifier of the GitHub OAuth2 token detector.
func (d *OAuthDetector) ID() string { return "github-oauth-token" }

// Description returns a human-readable description of the GitHub OAuth2 token detector.
func (d *OAuthDetector) Description() string { return "GitHub OAuth2 Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for GitHub OAuth2 token detection.
func (d *OAuthDetector) Keywords() []string { return []string{"gho_", "ghu_", "ghr_", "ghs_"} }

// Severity returns the default severity level for GitHub OAuth2 token findings.
func (d *OAuthDetector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan scans the given data for GitHub OAuth2 Token patterns.
func (d *OAuthDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := oauthTokenPattern.FindAll(data, -1)
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
	detector.Register(&OAuthDetector{})
}
