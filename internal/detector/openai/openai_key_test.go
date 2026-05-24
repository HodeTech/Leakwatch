package openai

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "openai-api-key", d.ID())
	assert.Equal(t, "OpenAI API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 50-char suffix
	suffix50 := strings.Repeat("Abc1", 12) + "Xy"
	// synthetic 85-char suffix (valid but longer)
	suffix85 := strings.Repeat("Abc1", 21) + "X"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with 50 char suffix",
			input:    "sk-proj-" + suffix50,
			expected: 1,
			redacted: "****" + ("sk-proj-" + suffix50)[len("sk-proj-"+suffix50)-4:],
		},
		{
			name:     "valid key with longer suffix",
			input:    "sk-proj-" + suffix85,
			expected: 1,
			redacted: "****" + ("sk-proj-" + suffix85)[len("sk-proj-"+suffix85)-4:],
		},
		{
			name:     "key embedded in config",
			input:    `OPENAI_API_KEY=sk-proj-` + suffix50,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "sk-proj-abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "sk-live-" + suffix50,
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
				assert.NotContains(t, findings[0].Redacted, suffix50)
			}
		})
	}
}
