package slack

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var webhookPattern = regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,48}`)

// Webhook detects Slack Incoming Webhook URLs.
type Webhook struct{}

// ID returns the unique identifier of the Slack webhook detector.
func (d *Webhook) ID() string { return "slack-webhook" }

// Description returns a human-readable description of the Slack webhook detector.
func (d *Webhook) Description() string { return "Slack Webhook URL" }

// Keywords returns the Aho-Corasick pre-filter keywords for Slack webhook detection.
func (d *Webhook) Keywords() []string { return []string{"hooks.slack.com"} }

// Severity returns the default severity level for Slack webhook findings.
func (d *Webhook) Severity() finding.Severity { return finding.SeverityHigh }

// Scan scans the given data for Slack Webhook URL patterns.
func (d *Webhook) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := webhookPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		// Redact the final token segment of the webhook URL.
		lastSlash := len(s) - 1
		for lastSlash >= 0 && s[lastSlash] != '/' {
			lastSlash--
		}
		redacted := s[:lastSlash+1] + "****"
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redacted,
		})
	}
	return findings
}

func init() {
	detector.Register(&Webhook{})
}
