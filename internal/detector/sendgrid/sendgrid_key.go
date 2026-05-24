// Package sendgrid provides a SendGrid API Key secret detector.
package sendgrid

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var sendGridKeyPattern = regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`)

// Detector detects SendGrid API Keys.
type Detector struct{}

func (d *Detector) ID() string { return "sendgrid-api-key" }

func (d *Detector) Description() string { return "SendGrid API Key" }

func (d *Detector) Keywords() []string { return []string{"SG."} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for SendGrid API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := sendGridKeyPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "SG.****" + string(match[len(match)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
