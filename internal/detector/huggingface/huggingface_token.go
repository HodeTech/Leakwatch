// Package huggingface provides a Hugging Face API Token secret detector.
package huggingface

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var huggingFaceTokenPattern = regexp.MustCompile(`hf_[A-Za-z0-9]{34,}`)

// Detector detects Hugging Face API Tokens.
type Detector struct{}

// ID returns the unique identifier of the Hugging Face Token detector.
func (d *Detector) ID() string { return "huggingface-token" }

// Description returns a human-readable description of the Hugging Face Token detector.
func (d *Detector) Description() string { return "Hugging Face API Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Hugging Face Token detection.
func (d *Detector) Keywords() []string { return []string{"hf_"} }

// Severity returns the default severity level for Hugging Face Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Hugging Face API Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := huggingFaceTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		s := string(match)
		last4 := s[len(s)-4:]
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "hf_****" + last4,
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
