package anthropic

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
	assert.Equal(t, "anthropic-api-key", d.ID())
	assert.Equal(t, "Anthropic API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 85-char suffix
	suffix85 := strings.Repeat("Abc1", 21) + "X"
	// synthetic 100-char suffix (longer, still valid)
	suffix100 := strings.Repeat("Abc1", 25)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with 85 char suffix",
			input:    "sk-ant-" + suffix85,
			expected: 1,
			redacted: "****" + ("sk-ant-" + suffix85)[len("sk-ant-"+suffix85)-4:],
		},
		{
			name:     "valid key with longer suffix",
			input:    "sk-ant-" + suffix100,
			expected: 1,
			redacted: "****" + ("sk-ant-" + suffix100)[len("sk-ant-"+suffix100)-4:],
		},
		{
			name:     "key embedded in env var",
			input:    `ANTHROPIC_API_KEY="sk-ant-` + suffix85 + `"`,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "sk-ant-abc123def456",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "sk-xyz-" + suffix85,
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
				assert.NotContains(t, findings[0].Redacted, suffix85)
			}
		})
	}
}
