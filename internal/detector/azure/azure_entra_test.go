package azure

import (
	"context"
	"strings"
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntraDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &EntraDetector{}
	assert.Equal(t, "azure-entra-secret", d.ID())
	assert.Equal(t, "Azure Entra ID Client Secret", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestEntraDetector_Scan_MatchesValidSecrets(t *testing.T) {
	// synthetic 36-char secret: alphanumeric with allowed special chars
	secret36 := strings.Repeat("aB3~._-x", 4) + "aB3~"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
		secret   string
	}{
		{
			name:     "AZURE_CLIENT_SECRET with equals",
			input:    "AZURE_CLIENT_SECRET=" + secret36,
			expected: 1,
			redacted: "****aB3~",
			secret:   secret36,
		},
		{
			name:     "azure_client_secret with colon and quotes",
			input:    `azure_client_secret: "` + secret36 + `"`,
			expected: 1,
			redacted: "****aB3~",
			secret:   secret36,
		},
		{
			name:     "client_secret with equals and single quotes",
			input:    "client_secret = '" + secret36 + "'",
			expected: 1,
			redacted: "****aB3~",
			secret:   secret36,
		},
		{
			name:     "AZURE_CLIENT_SECRET with spaces around equals",
			input:    "AZURE_CLIENT_SECRET = " + secret36,
			expected: 1,
			redacted: "****aB3~",
			secret:   secret36,
		},
		{
			name:     "client_secret in YAML format",
			input:    "client_secret: " + secret36,
			expected: 1,
			redacted: "****aB3~",
			secret:   secret36,
		},
	}

	d := &EntraDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
				assert.Equal(t, tt.secret, string(findings[0].Raw))
			}
		})
	}
}

func TestEntraDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "secret too short",
			input: "AZURE_CLIENT_SECRET=abc123",
		},
		{
			name:  "secret with invalid chars",
			input: "AZURE_CLIENT_SECRET=abc!@#$%^&*()_invalid_chars!!",
		},
		{
			name:  "no assignment operator",
			input: "AZURE_CLIENT_SECRET is not set",
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

	d := &EntraDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}
