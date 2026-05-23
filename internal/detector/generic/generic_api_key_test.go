package generic

import (
	"context"
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyDetector_Metadata(t *testing.T) {
	d := &APIKeyDetector{}
	assert.Equal(t, "generic-api-key", d.ID())
	assert.Equal(t, finding.SeverityMedium, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestAPIKeyDetector_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "api_key with equals",
			input:    `api_key = "abcdef1234567890abcdef1234567890"`,
			expected: 1,
		},
		{
			name:     "API_KEY with equals",
			input:    `API_KEY = "abcdef1234567890abcdef1234567890"`,
			expected: 1,
		},
		{
			name:     "api-key with colon",
			input:    `api-key: abcdef1234567890abcdef1234567890`,
			expected: 1,
		},
		{
			name:     "secret_key with equals",
			input:    `secret_key = "abcdef1234567890abcdef1234567890"`,
			expected: 1,
		},
		{
			name:     "api_secret with colon",
			input:    `api_secret: abcdef1234567890abcdef1234567890`,
			expected: 1,
		},
		{
			name:     "value too short",
			input:    `api_key = "short"`,
			expected: 0,
		},
		{
			name:     "no assignment pattern",
			input:    "just some api_key mention in text",
			expected: 0,
		},
		{
			name:     "plain text",
			input:    "no secrets here",
			expected: 0,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name:     "multiple keys",
			input:    "api_key = \"abcdef1234567890abcdef1234567890\"\nsecret_key = \"1234567890abcdef1234567890abcdef\"",
			expected: 2,
		},
		{
			name:     "base64 value",
			input:    `api_key = "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciBsZWFrd2F0Y2g="`,
			expected: 1,
		},
	}

	d := &APIKeyDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
		})
	}
}

func TestAPIKeyDetector_Scan_RedactsValue(t *testing.T) {
	d := &APIKeyDetector{}
	input := `api_key = "abcdef1234567890abcdef1234567890"`

	findings := d.Scan(context.Background(), []byte(input))
	require.Len(t, findings, 1)

	assert.Equal(t, "****7890", findings[0].Redacted)
	assert.Equal(t, "api_key", findings[0].ExtraData["key_name"])
}

func TestAPIKeyDetector_Scan_LowEntropy_SkipsMatch(t *testing.T) {
	d := &APIKeyDetector{}
	// Low entropy value: repeating character sequence
	input := `api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`

	findings := d.Scan(context.Background(), []byte(input))
	assert.Empty(t, findings, "low entropy value should be skipped")
}
