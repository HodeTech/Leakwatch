package sentry

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
	assert.Equal(t, "sentry-token", d.ID())
	assert.Equal(t, "Sentry Auth Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 40-char suffix
	suffix40 := strings.Repeat("Abc1", 10)
	// synthetic 60-char suffix (valid but longer)
	suffix60 := strings.Repeat("Abc1", 15)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 40 char suffix",
			input:    "sntrys_" + suffix40,
			expected: 1,
			redacted: "sntrys_****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "valid token with longer suffix",
			input:    "sntrys_" + suffix60,
			expected: 1,
			redacted: "sntrys_****" + suffix60[len(suffix60)-4:],
		},
		{
			name:     "token embedded in config",
			input:    `SENTRY_AUTH_TOKEN=sntrys_` + suffix40,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "sntrys_abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "sntry_" + suffix40,
			expected: 0,
		},
		{
			name:     "no match - plain text",
			input:    "this is just normal text",
			expected: 0,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
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
