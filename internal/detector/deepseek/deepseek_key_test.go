package deepseek

import (
	"context"
	"strings"
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "deepseek-api-key", d.ID())
	assert.Equal(t, "DeepSeek API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesWithContext(t *testing.T) {
	// synthetic 32-char hex suffix
	suffix32 := strings.Repeat("abcdef01", 4)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with deepseek keyword before",
			input:    "DEEPSEEK_API_KEY=sk-" + suffix32,
			expected: 1,
			redacted: "****ef01",
		},
		{
			name:     "valid key with deepseek keyword after",
			input:    "sk-" + suffix32 + " # deepseek api key",
			expected: 1,
			redacted: "****ef01",
		},
		{
			name:     "valid key with deep_seek keyword",
			input:    "deep_seek_key=sk-" + suffix32,
			expected: 1,
			redacted: "****ef01",
		},
		{
			name:     "key in config block with context",
			input:    "[deepseek]\napi_key = sk-" + suffix32,
			expected: 1,
			redacted: "****ef01",
		},
		{
			name:     "no match - sk- key without deepseek context",
			input:    "SOME_OTHER_KEY=sk-" + suffix32,
			expected: 0,
		},
		{
			name:     "no match - openai sk-proj pattern",
			input:    "OPENAI_KEY=sk-proj-" + strings.Repeat("A", 50),
			expected: 0,
		},
		{
			name:     "no match - too short hex",
			input:    "deepseek key=sk-abc123",
			expected: 0,
		},
		{
			name:     "no match - plain text",
			input:    "this is just normal text",
			expected: 0,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
			}
		})
	}
}

func TestDetector_Scan_ContextWindowBoundary(t *testing.T) {
	suffix32 := strings.Repeat("abcdef01", 4)

	// Place keyword exactly at contextWindow+1 chars away (should NOT match).
	padding := strings.Repeat("x", contextWindow+1)
	input := "deepseek" + padding + "sk-" + suffix32

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(input))
	assert.Empty(t, findings, "keyword outside context window should not trigger match")
}
