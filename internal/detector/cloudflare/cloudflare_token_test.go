package cloudflare

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
	assert.Equal(t, "cloudflare-api-token", d.ID())
	assert.Equal(t, "Cloudflare API Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 40-char token
	token40 := strings.Repeat("AbCd1234", 5)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "CF_API_TOKEN with equals",
			input:    "CF_API_TOKEN=" + token40,
			expected: 1,
			redacted: "****" + token40[len(token40)-4:],
		},
		{
			name:     "CLOUDFLARE_API_TOKEN with equals",
			input:    "CLOUDFLARE_API_TOKEN=" + token40,
			expected: 1,
			redacted: "****" + token40[len(token40)-4:],
		},
		{
			name:     "cloudflare_api_token lowercase with equals",
			input:    "cloudflare_api_token=" + token40,
			expected: 1,
			redacted: "****" + token40[len(token40)-4:],
		},
		{
			name:     "cf_api_key with colon separator",
			input:    "cf_api_key: " + token40,
			expected: 1,
			redacted: "****" + token40[len(token40)-4:],
		},
		{
			name:     "CF_API_TOKEN with single quotes",
			input:    "CF_API_TOKEN='" + token40 + "'",
			expected: 1,
			redacted: "****" + token40[len(token40)-4:],
		},
		{
			name:     "CF_API_TOKEN with double quotes",
			input:    `CF_API_TOKEN="` + token40 + `"`,
			expected: 1,
			redacted: "****" + token40[len(token40)-4:],
		},
		{
			name:     "CF_API_TOKEN with spaces around equals",
			input:    "CF_API_TOKEN = " + token40,
			expected: 1,
			redacted: "****" + token40[len(token40)-4:],
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
				assert.Len(t, findings[0].Raw, 40)
			}
		})
	}
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	token40 := strings.Repeat("AbCd1234", 5)

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "no context keyword present",
			input: "API_TOKEN=" + token40,
		},
		{
			name:  "too short token value",
			input: "CF_API_TOKEN=abc123",
		},
		{
			name:  "plain text with cloudflare mention",
			input: "cloudflare is a great CDN provider",
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
