package figma

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
	assert.Equal(t, "figma-pat", d.ID())
	assert.Equal(t, "Figma Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 40-char suffix
	suffix40 := strings.Repeat("Ab1Cd2Ef", 5)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 40 char suffix",
			input:    "figd_" + suffix40,
			expected: 1,
			redacted: "figd_****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "valid token with longer suffix",
			input:    "figd_" + suffix40 + "ExtraChars",
			expected: 1,
			redacted: "figd_****hars",
		},
		{
			name:     "token embedded in config",
			input:    `FIGMA_TOKEN=figd_` + suffix40,
			expected: 1,
			redacted: "figd_****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "token with hyphens and underscores",
			input:    "figd_" + strings.Repeat("Ab-_Cd12", 5),
			expected: 1,
		},
		{
			name:     "multiple tokens in input",
			input:    "figd_" + suffix40 + "\nfigd_" + strings.Repeat("Xy9Zw8Ab", 5),
			expected: 2,
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

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "too short suffix",
			input: "figd_abc123",
		},
		{
			name:  "wrong prefix",
			input: "figx_" + strings.Repeat("Ab1Cd2Ef", 5),
		},
		{
			name:  "plain text",
			input: "this is just normal text about figma",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}
