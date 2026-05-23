package coinbase

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
	assert.Equal(t, "coinbase-api-key", d.ID())
	assert.Equal(t, "Coinbase API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidKeys(t *testing.T) {
	// Synthetic 32-char base64-like key
	key32 := strings.Repeat("AbCd1234", 4)
	// Synthetic 16-char key (minimum length)
	key16 := strings.Repeat("AbCd", 4)
	// Synthetic 64-char key (maximum length)
	key64 := strings.Repeat("AbCd1234", 8)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "COINBASE_API_KEY with equals",
			input:    "COINBASE_API_KEY=" + key32,
			expected: 1,
			redacted: "****" + key32[len(key32)-4:],
		},
		{
			name:     "coinbase_api_key lowercase with equals",
			input:    "coinbase_api_key=" + key32,
			expected: 1,
			redacted: "****" + key32[len(key32)-4:],
		},
		{
			name:     "coinbase_api_secret with equals",
			input:    "coinbase_api_secret=" + key32,
			expected: 1,
			redacted: "****" + key32[len(key32)-4:],
		},
		{
			name:     "COINBASE_API_KEY with colon separator",
			input:    "COINBASE_API_KEY: " + key32,
			expected: 1,
			redacted: "****" + key32[len(key32)-4:],
		},
		{
			name:     "COINBASE_API_KEY with single quotes",
			input:    "COINBASE_API_KEY='" + key32 + "'",
			expected: 1,
			redacted: "****" + key32[len(key32)-4:],
		},
		{
			name:     "COINBASE_API_KEY with double quotes",
			input:    `COINBASE_API_KEY="` + key32 + `"`,
			expected: 1,
			redacted: "****" + key32[len(key32)-4:],
		},
		{
			name:     "minimum length key 16 chars",
			input:    "COINBASE_API_KEY=" + key16,
			expected: 1,
			redacted: "****" + key16[len(key16)-4:],
		},
		{
			name:     "maximum length key 64 chars",
			input:    "COINBASE_API_KEY=" + key64,
			expected: 1,
			redacted: "****" + key64[len(key64)-4:],
		},
		{
			name:     "key with base64 padding chars",
			input:    "COINBASE_API_KEY=AbCdEfGh12345678+/==",
			expected: 1,
			redacted: "****" + "+/==",
		},
		{
			name:     "spaces around equals",
			input:    "COINBASE_API_KEY = " + key32,
			expected: 1,
			redacted: "****" + key32[len(key32)-4:],
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
			name:  "value too short",
			input: "COINBASE_API_KEY=abc123",
		},
		{
			name:  "value with invalid chars",
			input: "COINBASE_API_KEY=abc!@#$%^&*()invalid",
		},
		{
			name:  "no recognized variable name",
			input: "API_KEY=" + strings.Repeat("a", 32),
		},
		{
			name:  "special characters in value",
			input: "COINBASE_API_KEY=ab!@#$%^&*()_+1234567890123456",
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
