package vercel

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
	assert.Equal(t, "vercel-token", d.ID())
	assert.Equal(t, "Vercel API Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 24-char suffix
	suffix24 := strings.Repeat("Ab1x", 6)
	// synthetic 40-char suffix (valid but longer)
	suffix40 := strings.Repeat("Ab1x", 10)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 24 char suffix",
			input:    "vercel_" + suffix24,
			expected: 1,
			redacted: "vercel_****" + suffix24[len(suffix24)-4:],
		},
		{
			name:     "valid token with longer suffix",
			input:    "vercel_" + suffix40,
			expected: 1,
			redacted: "vercel_****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "token embedded in config",
			input:    `VERCEL_TOKEN=vercel_` + suffix24,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "vercel_abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "vercl_" + suffix24,
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
