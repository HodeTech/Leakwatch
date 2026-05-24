package rubygems

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
	assert.Equal(t, "rubygems-api-key", d.ID())
	assert.Equal(t, "RubyGems API Key", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 48-char hex suffix
	suffix48 := strings.Repeat("a1b2c3d4", 6)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with 48 hex chars",
			input:    "rubygems_" + suffix48,
			expected: 1,
			redacted: "rubygems_****" + suffix48[len(suffix48)-4:],
		},
		{
			name:     "key embedded in env",
			input:    `GEM_HOST_API_KEY=rubygems_` + suffix48,
			expected: 1,
		},
		{
			name:     "no match - too short hex",
			input:    "rubygems_a1b2c3d4",
			expected: 0,
		},
		{
			name:     "no match - uppercase hex",
			input:    "rubygems_" + strings.Repeat("A1B2C3D4", 6),
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "npmtoken_" + suffix48,
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
