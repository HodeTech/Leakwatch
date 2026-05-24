package linear

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
	assert.Equal(t, "linear-api-key", d.ID())
	assert.Equal(t, "Linear API Key", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidKeys(t *testing.T) {
	// Synthetic 40-char alphanumeric suffix
	suffix40 := strings.Repeat("Ab1Cd2Ef", 5)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with 40 char suffix",
			input:    "lin_api_" + suffix40,
			expected: 1,
			redacted: "lin_api_****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "valid key with longer suffix",
			input:    "lin_api_" + suffix40 + "ExtraChars",
			expected: 1,
			redacted: "lin_api_****hars",
		},
		{
			name:     "key embedded in config",
			input:    `LINEAR_API_KEY=lin_api_` + suffix40,
			expected: 1,
			redacted: "lin_api_****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "multiple keys in input",
			input:    "lin_api_" + suffix40 + "\nlin_api_" + strings.Repeat("Xy9Zw8Ab", 5),
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
			input: "lin_api_abc123",
		},
		{
			name:  "wrong prefix",
			input: "lin_key_" + strings.Repeat("Ab1Cd2Ef", 5),
		},
		{
			name:  "plain text",
			input: "this is just normal text",
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
