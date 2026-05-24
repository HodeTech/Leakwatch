package infura

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "infura-api-key", d.ID())
	assert.Equal(t, "Infura API Key", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidKeys(t *testing.T) {
	// Synthetic 32-char hex key
	hexKey32 := "abcdef0123456789abcdef0123456789"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "INFURA_API_KEY with equals",
			input:    "INFURA_API_KEY=" + hexKey32,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "infura_api_key lowercase with equals",
			input:    "infura_api_key=" + hexKey32,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "infura with colon separator",
			input:    "infura: " + hexKey32,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "INFURA_API_KEY with single quotes",
			input:    "INFURA_API_KEY='" + hexKey32 + "'",
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "INFURA_API_KEY with double quotes",
			input:    `INFURA_API_KEY="` + hexKey32 + `"`,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
		},
		{
			name:     "spaces around equals",
			input:    "INFURA_API_KEY = " + hexKey32,
			expected: 1,
			redacted: "****" + hexKey32[len(hexKey32)-4:],
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
				// Raw should contain only the 32-char hex key
				assert.Len(t, findings[0].Raw, 32)
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
			name:  "non-hex characters in key",
			input: "INFURA_API_KEY=ghijklmnopqrstuvwxyz0123456789ab",
		},
		{
			name:  "too short hex value",
			input: "INFURA_API_KEY=abcdef0123456789",
		},
		{
			name:  "non-hex characters",
			input: "INFURA_API_KEY=ghijklmnopqrstuvwxyz012345678901",
		},
		{
			name:  "no recognized variable name",
			input: "API_KEY=abcdef0123456789abcdef0123456789",
		},
		{
			name:  "uppercase hex not matched",
			input: "INFURA_API_KEY=ABCDEF0123456789ABCDEF0123456789",
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
