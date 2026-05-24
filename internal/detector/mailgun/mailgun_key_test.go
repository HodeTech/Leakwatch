package mailgun

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
	assert.Equal(t, "mailgun-api-key", d.ID())
	assert.Equal(t, "Mailgun API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidKeys(t *testing.T) {
	// Synthetic 32-char hex string
	hex32 := "abcdef0123456789abcdef0123456789"
	hex32alt := "0123456789abcdef0123456789abcdef"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid mailgun key standalone",
			input:    "key-" + hex32,
			expected: 1,
			redacted: "key-****" + hex32[len(hex32)-4:],
		},
		{
			name:     "valid mailgun key in config",
			input:    "MAILGUN_API_KEY=key-" + hex32,
			expected: 1,
			redacted: "key-****" + hex32[len(hex32)-4:],
		},
		{
			name:     "valid mailgun key with quotes",
			input:    `mailgun_api_key="key-` + hex32 + `"`,
			expected: 1,
			redacted: "key-****" + hex32[len(hex32)-4:],
		},
		{
			name:     "multiple keys in same input",
			input:    "MAILGUN_KEY1=key-" + hex32 + "\nMAILGUN_KEY2=key-" + hex32alt,
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
				assert.Len(t, findings[0].Raw, 36) // "key-" + 32 hex chars
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
			name:  "too short hex after key- prefix",
			input: "mailgun_key=key-abcdef0123",
		},
		{
			name:  "uppercase hex rejected",
			input: "mailgun_key=key-" + strings.ToUpper(strings.Repeat("ab", 16)),
		},
		{
			name:  "wrong prefix",
			input: "mailgun_key=api-" + strings.Repeat("a", 32),
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
