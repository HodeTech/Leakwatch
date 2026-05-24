package vault

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
	assert.Equal(t, "hashicorp-vault-token", d.ID())
	assert.Equal(t, "HashiCorp Vault Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 24-char suffix (minimum length)
	suffix24 := strings.Repeat("AbcD12", 4)
	// Synthetic 48-char suffix (longer token)
	suffix48 := strings.Repeat("AbcD12", 8)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with minimum 24 char suffix",
			input:    "hvs." + suffix24,
			expected: 1,
			redacted: "hvs.****" + suffix24[len(suffix24)-4:],
		},
		{
			name:     "valid token with longer suffix",
			input:    "hvs." + suffix48,
			expected: 1,
			redacted: "hvs.****" + suffix48[len(suffix48)-4:],
		},
		{
			name:     "token in VAULT_TOKEN env var",
			input:    "VAULT_TOKEN=hvs." + suffix24,
			expected: 1,
			redacted: "hvs.****" + suffix24[len(suffix24)-4:],
		},
		{
			name:     "token in vault_token lowercase",
			input:    "vault_token=hvs." + suffix48,
			expected: 1,
			redacted: "hvs.****" + suffix48[len(suffix48)-4:],
		},
		{
			name:     "token with underscores and dashes",
			input:    "hvs." + strings.Repeat("Ab_-", 6),
			expected: 1,
		},
		{
			name:     "multiple tokens in same input",
			input:    "VAULT_TOKEN=hvs." + suffix24 + "\nvault_token=hvs." + suffix48,
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
				assert.True(t, strings.HasPrefix(string(findings[0].Raw), "hvs."))
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
			name:  "too short suffix after hvs.",
			input: "hvs.abcdef0123",
		},
		{
			name:  "wrong prefix",
			input: "hvb." + strings.Repeat("a", 24),
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
		{
			name:  "hvs without dot",
			input: "hvsABCDEFGHIJKLMNOPQRSTUVWX",
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
