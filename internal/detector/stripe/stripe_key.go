// Package stripe provides detectors for Stripe secret types.
package stripe

import (
	"context"
	"regexp"
	"strings"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var keyPattern = regexp.MustCompile(`(sk|rk)_(live|test)_[a-zA-Z0-9]{24,99}`)

// Key detects Stripe API keys (secret and restricted).
type Key struct{}

func (d *Key) ID() string         { return "stripe-api-key" }
func (d *Key) Description() string { return "Stripe API Key" }
func (d *Key) Keywords() []string {
	return []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"}
}
func (d *Key) Severity() finding.Severity { return finding.SeverityCritical }

// Scan scans the given data for Stripe API key patterns.
// Live keys are reported as Critical severity, test keys as High.
func (d *Key) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := keyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		severity := "critical"
		if strings.Contains(s, "_test_") {
			severity = "high"
		}
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   s[:8] + "****" + s[len(s)-4:],
			ExtraData: map[string]string{
				"severity": severity,
			},
		})
	}
	return findings
}

func init() {
	detector.Register(&Key{})
}
