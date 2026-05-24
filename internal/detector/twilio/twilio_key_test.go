package twilio

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
	assert.Equal(t, "twilio-api-key", d.ID())
	assert.Equal(t, "Twilio API Key", d.Description())
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
		extraSID string
	}{
		{
			name:     "valid SK key with twilio context",
			input:    "twilio_api_key=SK" + hex32,
			expected: 1,
			redacted: "SK****" + hex32[len(hex32)-4:],
		},
		{
			name:     "valid SK key with Account SID in same data",
			input:    "TWILIO_ACCOUNT_SID=AC" + hex32alt + "\nTWILIO_API_KEY=SK" + hex32,
			expected: 1,
			redacted: "SK****" + hex32[len(hex32)-4:],
			extraSID: "AC" + hex32alt,
		},
		{
			name:     "multiple SK keys in same input",
			input:    "twilio_key1=SK" + hex32 + "\ntwilio_key2=SK" + hex32alt,
			expected: 2,
		},
		{
			name:     "SK key embedded in config line",
			input:    `TWILIO_API_KEY="SK` + hex32 + `"`,
			expected: 1,
			redacted: "SK****" + hex32[len(hex32)-4:],
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
				assert.Len(t, findings[0].Raw, 34) // "SK" + 32 hex chars
			}
			if tt.extraSID != "" {
				require.NotEmpty(t, findings)
				require.NotNil(t, findings[0].ExtraData)
				assert.Equal(t, tt.extraSID, findings[0].ExtraData["account_sid"])
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
			name:  "wrong prefix with twilio context",
			input: "twilio_key=AB" + strings.Repeat("a", 32),
		},
		{
			name:  "too short hex with twilio context",
			input: "twilio_key=SKabcdef0123",
		},
		{
			name:  "uppercase hex rejected",
			input: "twilio_key=SK" + strings.ToUpper(strings.Repeat("ab", 16)),
		},
		{
			name:  "Account SID alone is not a finding",
			input: "twilio_sid=AC" + strings.Repeat("a", 32),
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
