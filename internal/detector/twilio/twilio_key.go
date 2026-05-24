// Package twilio provides a Twilio API Key secret detector.
package twilio

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	twilioKeyPattern = regexp.MustCompile(`SK[a-f0-9]{32}`)
	twilioSIDPattern = regexp.MustCompile(`AC[a-f0-9]{32}`)
)

// Detector detects Twilio API Keys.
type Detector struct{}

// ID returns the unique identifier of the Twilio API Key detector.
func (d *Detector) ID() string { return "twilio-api-key" }

// Description returns a human-readable description of the Twilio API Key detector.
func (d *Detector) Description() string { return "Twilio API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for Twilio API Key detection.
func (d *Detector) Keywords() []string { return []string{"twilio", "TWILIO", "twilio_api"} }

// Severity returns the default severity level for Twilio API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Twilio API Key patterns.
// Account SID (AC prefix) is captured as ExtraData rather than a separate finding.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := twilioKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	// Look for Account SID to store as extra context.
	var accountSID string
	if sidMatch := twilioSIDPattern.Find(data); sidMatch != nil {
		accountSID = string(sidMatch)
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		redacted := "SK****" + string(match[len(match)-4:])
		f := detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   redacted,
		}
		if accountSID != "" {
			f.ExtraData = map[string]string{
				"account_sid": accountSID,
			}
		}
		findings = append(findings, f)
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
