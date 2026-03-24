// Package jwt provides a detector for JSON Web Tokens.
package jwt

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)

// JWT detects JSON Web Tokens.
type JWT struct{}

func (d *JWT) ID() string          { return "jwt" }
func (d *JWT) Description() string  { return "JSON Web Token" }
func (d *JWT) Keywords() []string   { return []string{"eyJ"} }
func (d *JWT) Severity() finding.Severity { return finding.SeverityHigh }

// Scan scans the given data for JSON Web Token patterns.
func (d *JWT) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := jwtPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		// Redact the signature portion (everything after the second dot).
		firstDot := -1
		secondDot := -1
		for i, c := range s {
			if c == '.' {
				if firstDot == -1 {
					firstDot = i
				} else {
					secondDot = i
					break
				}
			}
		}
		redacted := s[:secondDot+1] + "****"
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redacted,
		})
	}
	return findings
}

func init() {
	detector.Register(&JWT{})
}
