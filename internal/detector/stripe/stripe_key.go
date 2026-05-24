// Package stripe provides detectors for Stripe secret types.
package stripe

import (
	"context"
	"regexp"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	liveKeyPattern = regexp.MustCompile(`(sk|rk)_live_[a-zA-Z0-9]{24,99}`)
	testKeyPattern = regexp.MustCompile(`(sk|rk)_test_[a-zA-Z0-9]{24,99}`)
)

// LiveKey detects Stripe live API keys (secret and restricted).
type LiveKey struct{}

// ID returns the unique identifier of the Stripe live key detector.
func (d *LiveKey) ID() string { return "stripe-api-key-live" }

// Description returns a human-readable description of the Stripe live key detector.
func (d *LiveKey) Description() string { return "Stripe Live API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Stripe live key detection.
func (d *LiveKey) Keywords() []string {
	return []string{"sk_live_", "rk_live_"}
}

// Severity returns the default severity level for Stripe live key findings.
func (d *LiveKey) Severity() finding.Severity { return finding.SeverityCritical }

// Scan scans the given data for Stripe live API key patterns.
func (d *LiveKey) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := liveKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redactStripeKey(s),
		})
	}
	return findings
}

// TestKey detects Stripe test API keys (secret and restricted).
type TestKey struct{}

// ID returns the unique identifier of the Stripe test key detector.
func (d *TestKey) ID() string { return "stripe-api-key-test" }

// Description returns a human-readable description of the Stripe test key detector.
func (d *TestKey) Description() string { return "Stripe Test API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Stripe test key detection.
func (d *TestKey) Keywords() []string {
	return []string{"sk_test_", "rk_test_"}
}

// Severity returns the default severity level for Stripe test key findings.
func (d *TestKey) Severity() finding.Severity { return finding.SeverityHigh }

// Scan scans the given data for Stripe test API key patterns.
func (d *TestKey) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := testKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redactStripeKey(s),
		})
	}
	return findings
}

// redactStripeKey masks the secret portion of a Stripe key, preserving the prefix
// dynamically by finding the position after the second underscore.
func redactStripeKey(s string) string {
	// Find the prefix (e.g., "sk_live_" or "rk_test_") by locating the second underscore.
	firstUnderscore := strings.Index(s, "_")
	if firstUnderscore == -1 || firstUnderscore+1 >= len(s) {
		return "****"
	}
	secondUnderscore := strings.Index(s[firstUnderscore+1:], "_")
	if secondUnderscore == -1 {
		return "****"
	}
	prefixEnd := firstUnderscore + 1 + secondUnderscore + 1 // position after second '_'
	if prefixEnd >= len(s) {
		return "****"
	}
	suffix := ""
	if len(s) >= 4 {
		suffix = s[len(s)-4:]
	}
	return s[:prefixEnd] + "****" + suffix
}

func init() {
	detector.Register(&LiveKey{})
	detector.Register(&TestKey{})
}
