// Package anthropic provides an Anthropic API Key secret detector.
package anthropic

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var anthropicKeyPattern = regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{85,}`)

// Detector detects Anthropic API Keys.
type Detector struct{}

func (d *Detector) ID() string { return "anthropic-api-key" }

func (d *Detector) Description() string { return "Anthropic API Key" }

func (d *Detector) Keywords() []string { return []string{"sk-ant-"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Anthropic API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := anthropicKeyPattern.FindAll(data, -1)
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
