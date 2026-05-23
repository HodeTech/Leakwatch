package telegram

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
	assert.Equal(t, "telegram-bot-token", d.ID())
	assert.Equal(t, "Telegram Bot Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	// Telegram intentionally has no pre-filter keywords so the regex runs on
	// every chunk and standalone tokens are not gated out by the matcher.
	assert.Empty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 35-char alphanumeric suffix
	suffix35 := strings.Repeat("Ab1Cd", 7)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 8 digit bot ID",
			input:    "12345678:" + suffix35,
			expected: 1,
			redacted: "****" + suffix35[len(suffix35)-4:],
		},
		{
			name:     "valid token with 7 digit bot ID",
			input:    "1234567:" + suffix35,
			expected: 1,
			redacted: "****" + suffix35[len(suffix35)-4:],
		},
		{
			name:     "valid token with 10 digit bot ID",
			input:    "1234567890:" + suffix35,
			expected: 1,
			redacted: "****" + suffix35[len(suffix35)-4:],
		},
		{
			name:     "token in env var context",
			input:    "TELEGRAM_BOT_TOKEN=12345678:" + suffix35,
			expected: 1,
		},
		{
			name:     "token with underscores and hyphens in suffix",
			input:    "12345678:" + strings.Repeat("A_b-c", 7),
			expected: 1,
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

func TestDetector_Scan_RejectsInvalidTokens(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "too few digits before colon",
			input: "123456:" + strings.Repeat("a", 35),
		},
		{
			name:  "wrong separator instead of colon",
			input: "12345678-" + strings.Repeat("a", 35),
		},
		{
			name:  "suffix too short",
			input: "12345678:" + strings.Repeat("a", 20),
		},
		{
			name:  "no colon separator",
			input: "12345678" + strings.Repeat("a", 35),
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
