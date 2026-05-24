// Package teams provides a Microsoft Teams Incoming Webhook URL secret detector.
package teams

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var teamsWebhookPattern = regexp.MustCompile(`https://[a-zA-Z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9-]+`)

// Detector detects Microsoft Teams Incoming Webhook URLs.
type Detector struct{}

// ID returns the unique identifier of the Teams webhook detector.
func (d *Detector) ID() string { return "teams-webhook" }

// Description returns a human-readable description of the Teams webhook detector.
func (d *Detector) Description() string { return "Microsoft Teams Incoming Webhook URL" }

// Keywords returns the Aho-Corasick pre-filter keywords for Teams webhook detection.
func (d *Detector) Keywords() []string {
	return []string{"webhook.office.com", "IncomingWebhook"}
}

// Severity returns the default severity level for Teams webhook findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Microsoft Teams Incoming Webhook URL patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := teamsWebhookPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "https://****webhook.office.com/webhookb2/****",
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
