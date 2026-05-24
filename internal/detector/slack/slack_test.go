package slack

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Slack Token Tests ---

func TestToken_Metadata(t *testing.T) {
	d := &Token{}
	assert.Equal(t, "slack-token", d.ID())
	assert.Equal(t, "Slack Bot/User Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestToken_Scan_MatchesValidTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid xoxb bot token",
			input:    "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "****UvWx",
		},
		{
			name:     "valid xoxp user token",
			input:    "xoxp-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "****UvWx",
		},
		{
			name:     "valid xoxa app token",
			input:    "xoxa-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "****UvWx",
		},
		{
			name:     "valid xoxr refresh token",
			input:    "xoxr-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "****UvWx",
		},
		{
			name:     "token in env var",
			input:    `SLACK_TOKEN=xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx`,
			expected: 1,
		},
		{
			name:     "multiple tokens",
			input:    "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx xoxp-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 2,
		},
		{
			name:     "token in large text",
			input:    strings.Repeat("x", 10000) + "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx" + strings.Repeat("y", 10000),
			expected: 1,
		},
	}

	d := &Token{}
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

func TestToken_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "wrong prefix",
			input: "xoxz-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
		},
		{
			name:  "missing second number segment",
			input: "xoxb-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
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

	d := &Token{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

// --- Slack Webhook Tests ---

func TestWebhook_Metadata(t *testing.T) {
	d := &Webhook{}
	assert.Equal(t, "slack-webhook", d.ID())
	assert.Equal(t, "Slack Webhook URL", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestWebhook_Scan_MatchesValidWebhooks(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid webhook URL",
			input:    "https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
			redacted: "https://hooks.slack.com/services/T12345678/B12345678/****",
		},
		{
			name:     "webhook in config",
			input:    `SLACK_WEBHOOK="https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx"`,
			expected: 1,
		},
		{
			name:     "webhook with longer IDs",
			input:    "https://hooks.slack.com/services/T123456789AB/B123456789AB/AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 1,
		},
		{
			name:     "multiple webhooks",
			input:    "https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/ZyXwVuTsRqPoNmLkJiHgFeDc",
			expected: 2,
		},
		{
			name:     "webhook in large text",
			input:    strings.Repeat("a", 10000) + "https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx" + strings.Repeat("b", 10000),
			expected: 1,
		},
	}

	d := &Webhook{}
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

func TestWebhook_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "wrong domain",
			input: "https://hooks.example.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx",
		},
		{
			name:  "missing T prefix in workspace ID",
			input: "https://hooks.slack.com/services/X12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx",
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

	d := &Webhook{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}
