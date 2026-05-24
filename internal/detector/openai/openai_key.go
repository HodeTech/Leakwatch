// Package openai provides an OpenAI API Key secret detector.
package openai

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var openAIKeyPattern = regexp.MustCompile(`sk-proj-[A-Za-z0-9_-]{50,}`)

// Detector detects OpenAI API Keys.
type Detector struct{}

func (d *Detector) ID() string { return "openai-api-key" }

func (d *Detector) Description() string { return "OpenAI API Key" }

func (d *Detector) Keywords() []string { return []string{"sk-proj-"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for OpenAI API Key patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := openAIKeyPattern.FindAll(data, -1)
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
