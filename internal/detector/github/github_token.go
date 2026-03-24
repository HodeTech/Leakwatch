// Package github provides detectors for GitHub secret types.
package github

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var tokenPattern = regexp.MustCompile(`(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}`)

// Token detects GitHub Personal Access Tokens.
type Token struct{}

func (d *Token) ID() string          { return "github-token" }
func (d *Token) Description() string  { return "GitHub Personal Access Token" }
func (d *Token) Keywords() []string   { return []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} }
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
			Redacted:   string(match[:4]) + "****" + string(match[len(match)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Token{})
}
