package stripe

import (
	"context"
	"strings"
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKey_Metadata(t *testing.T) {
	d := &Key{}
	assert.Equal(t, "stripe-api-key", d.ID())
	assert.Equal(t, "Stripe API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestKey_Scan_MatchesValidKeys(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expected         int
		redacted         string
		expectedSeverity string
	}{
		{
			name:             "valid sk_live key",
			input:            "sk_live_AbCdEfGhIjKlMnOpQrStUvWx",
			expected:         1,
			redacted:         "sk_live_****UvWx",
			expectedSeverity: "critical",
		},
		{
			name:             "valid sk_test key",
			input:            "sk_test_AbCdEfGhIjKlMnOpQrStUvWx",
			expected:         1,
			redacted:         "sk_test_****UvWx",
			expectedSeverity: "high",
		},
		{
			name:             "valid rk_live key",
			input:            "rk_live_AbCdEfGhIjKlMnOpQrStUvWx",
			expected:         1,
			redacted:         "rk_live_****UvWx",
			expectedSeverity: "critical",
		},
		{
			name:             "valid rk_test key",
			input:            "rk_test_AbCdEfGhIjKlMnOpQrStUvWx",
			expected:         1,
			redacted:         "rk_test_****UvWx",
			expectedSeverity: "high",
		},
		{
			name:     "key in env var",
			input:    `STRIPE_SECRET_KEY=sk_live_AbCdEfGhIjKlMnOpQrStUvWx`,
			expected: 1,
		},
		{
			name:     "key in JSON",
			input:    `{"api_key": "sk_live_AbCdEfGhIjKlMnOpQrStUvWx"}`,
			expected: 1,
		},
		{
			name:     "multiple keys",
			input:    "sk_live_AbCdEfGhIjKlMnOpQrStUvWx sk_test_AbCdEfGhIjKlMnOpQrStUvWx",
			expected: 2,
		},
		{
			name:     "key in large text",
			input:    strings.Repeat("x", 10000) + "sk_live_AbCdEfGhIjKlMnOpQrStUvWx" + strings.Repeat("y", 10000),
			expected: 1,
		},
	}

	d := &Key{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
			}
			if tt.expectedSeverity != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.expectedSeverity, findings[0].ExtraData["severity"])
			}
		})
	}
}

func TestKey_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "too short key value",
			input: "sk_live_short",
		},
		{
			name:  "wrong prefix",
			input: "pk_live_AbCdEfGhIjKlMnOpQrStUvWx",
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

	d := &Key{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}
