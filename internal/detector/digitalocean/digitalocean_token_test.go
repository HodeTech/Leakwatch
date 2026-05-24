package digitalocean

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
	assert.Equal(t, "digitalocean-token", d.ID())
	assert.Equal(t, "DigitalOcean Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 64-char hex suffix
	suffix64 := strings.Repeat("a1b2c3d4", 8)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 64 hex chars",
			input:    "dop_v1_" + suffix64,
			expected: 1,
			redacted: "dop_v1_****" + suffix64[len(suffix64)-4:],
		},
		{
			name:     "token embedded in env",
			input:    `DO_TOKEN=dop_v1_` + suffix64,
			expected: 1,
		},
		{
			name:     "no match - too short hex",
			input:    "dop_v1_a1b2c3d4",
			expected: 0,
		},
		{
			name:     "no match - uppercase hex",
			input:    "dop_v1_" + strings.Repeat("A1B2C3D4", 8),
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "do_pat_" + suffix64,
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
