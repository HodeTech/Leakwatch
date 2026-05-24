// Package deepseek provides a DeepSeek API Key secret detector.
package deepseek

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var deepSeekKeyPattern = regexp.MustCompile(`sk-[a-f0-9]{32,}`)

// contextWindow defines how many bytes before/after a match to search for
// DeepSeek-specific keywords, preventing collisions with other sk- prefixed keys.
const contextWindow = 200

// contextKeywords contains lowercase keywords that indicate a DeepSeek context.
var contextKeywords = [][]byte{
	[]byte("deepseek"),
	[]byte("DEEPSEEK"),
	[]byte("deep_seek"),
}

// Detector detects DeepSeek API Keys.
type Detector struct{}

// ID returns the unique identifier of the DeepSeek API Key detector.
func (d *Detector) ID() string { return "deepseek-api-key" }

// Description returns a human-readable description of the DeepSeek API Key detector.
func (d *Detector) Description() string { return "DeepSeek API Key" }

// Keywords returns the Aho-Corasick pre-filter keywords for DeepSeek API Key detection.
func (d *Detector) Keywords() []string {
	return []string{"deepseek", "DEEPSEEK", "deep_seek"}
}

// Severity returns the default severity level for DeepSeek API Key findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for DeepSeek API Key patterns. It verifies that a
// DeepSeek-specific keyword exists within 200 characters before or after each
// match to differentiate from other sk- prefixed keys (e.g., OpenAI sk-proj-).
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allIndexes := deepSeekKeyPattern.FindAllIndex(data, -1)
	if len(allIndexes) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allIndexes))
	for _, loc := range allIndexes {
		match := data[loc[0]:loc[1]]

		// Determine context window boundaries.
		ctxStart := loc[0] - contextWindow
		if ctxStart < 0 {
			ctxStart = 0
		}
		ctxEnd := loc[1] + contextWindow
		if ctxEnd > len(data) {
			ctxEnd = len(data)
		}
		window := data[ctxStart:ctxEnd]

		if !hasContextKeyword(window) {
			continue
		}

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   detector.RedactBytes(match),
		})
	}
	return findings
}

// hasContextKeyword checks whether any DeepSeek-specific keyword is present
// in the given byte slice.
func hasContextKeyword(data []byte) bool {
	for _, kw := range contextKeywords {
		if bytes.Contains(data, kw) {
			return true
		}
	}
	return false
}

func init() {
	detector.Register(&Detector{})
}
