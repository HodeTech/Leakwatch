// Package telegram provides a Telegram Bot Token secret detector.
package telegram

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var telegramTokenPattern = regexp.MustCompile(`[0-9]{7,10}:[A-Za-z0-9_-]{35}`)

// Detector detects Telegram Bot Tokens.
type Detector struct{}

// ID returns the unique identifier of the Telegram Bot Token detector.
func (d *Detector) ID() string { return "telegram-bot-token" }

// Description returns a human-readable description of the Telegram Bot Token detector.
func (d *Detector) Description() string { return "Telegram Bot Token" }

// Keywords returns the Aho-Corasick pre-filter keywords.
// A Telegram Bot Token (digits ":" 35-char secret) has no fixed keyword that
// the regex requires, so an empty slice is returned to ensure the regex runs on
// every chunk. Gating on "telegram"/"bot_token" would miss standalone tokens
// such as "123456789:AAH..." that do not carry those words.
func (d *Detector) Keywords() []string { return []string{} }

// Severity returns the default severity level for Telegram Bot Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityHigh }

// Scan searches the data for Telegram Bot Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := telegramTokenPattern.FindAll(data, -1)
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
	detector.Register(&Detector{})
}
