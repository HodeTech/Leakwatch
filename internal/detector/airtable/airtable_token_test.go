package airtable

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
	assert.Equal(t, "airtable-pat", d.ID())
	assert.Equal(t, "Airtable Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 14-char alphanumeric prefix part (after "pat")
	prefix14 := "Ab1Cd2Ef3Gh4Ij"
	// Synthetic 64-char lowercase hex suffix
	hex64 := strings.Repeat("abcdef01", 8)

	token := "pat" + prefix14 + "." + hex64

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token standalone",
			input:    token,
			expected: 1,
			redacted: "****" + token[len(token)-4:],
		},
		{
			name:     "token embedded in config",
			input:    "AIRTABLE_API_KEY=" + token,
			expected: 1,
			redacted: "****" + token[len(token)-4:],
		},
		{
			name:     "token in environment variable",
			input:    "export AIRTABLE_TOKEN='" + token + "'",
			expected: 1,
			redacted: "****" + token[len(token)-4:],
		},
		{
			name:     "multiple tokens",
			input:    token + "\n" + "pat" + "Xy9Zw8Ab1Cd2Ef" + "." + strings.Repeat("01234567", 8),
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
			name:  "too short prefix part",
			input: "patAb1Cd.abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
		},
		{
			name:  "missing dot separator",
			input: "patAb1Cd2Ef3Gh4Ij" + strings.Repeat("abcdef01", 8),
		},
		{
			name:  "hex part too short",
			input: "patAb1Cd2Ef3Gh4Ij.abcdef01",
		},
		{
			name:  "uppercase hex in suffix",
			input: "patAb1Cd2Ef3Gh4Ij." + strings.Repeat("ABCDEF01", 8),
		},
		{
			name:  "plain text",
			input: "this is just normal text about airtable",
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
