package slack

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var webhookPattern = regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}`)

// Webhook detects Slack Incoming Webhook URLs.
type Webhook struct{}

func (d *Webhook) ID() string          { return "slack-webhook" }
func (d *Webhook) Description() string  { return "Slack Webhook URL" }
func (d *Webhook) Keywords() []string   { return []string{"hooks.slack.com"} }
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
