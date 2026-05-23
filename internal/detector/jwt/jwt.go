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

// ID returns the unique identifier of the JWT detector.
func (d *JWT) ID() string { return "jwt" }

// Description returns a human-readable description of the JWT detector.
func (d *JWT) Description() string { return "JSON Web Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for JWT detection.
func (d *JWT) Keywords() []string { return []string{"eyJ"} }

// Severity returns the default severity level for JWT findings.
func (d *JWT) Severity() finding.Severity { return finding.SeverityHigh }

// Scan scans the given data for JSON Web Token patterns.
func (d *JWT) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := jwtPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		// Reveal only the trailing characters to avoid exposing the JWT
		// header, payload, or signature.
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   detector.RedactBytes(match),
		})
	}
	return findings
}

func init() {
	detector.Register(&JWT{})
}
