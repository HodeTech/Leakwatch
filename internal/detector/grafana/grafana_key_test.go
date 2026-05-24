package grafana

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
	assert.Equal(t, "grafana-api-key", d.ID())
	assert.Equal(t, "Grafana API Key", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// Synthetic 32-char random portion + 8-char hex suffix
	random32 := strings.Repeat("AbcD1234", 4)
	hexSuffix := "a1b2c3d4"
	validKey := "glsa_" + random32 + "_" + hexSuffix

	// Longer random portion (48 chars)
	random48 := strings.Repeat("AbcD1234", 6)
	longerKey := "glsa_" + random48 + "_" + hexSuffix

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid key with 32 char random",
			input:    validKey,
			expected: 1,
			redacted: "glsa_****" + hexSuffix[4:],
		},
		{
			name:     "valid key with longer random",
			input:    longerKey,
			expected: 1,
			redacted: "glsa_****" + hexSuffix[4:],
		},
		{
			name:     "key embedded in config",
			input:    `GRAFANA_API_KEY=` + validKey,
			expected: 1,
		},
		{
			name:     "no match - random too short",
			input:    "glsa_abc123_a1b2c3d4",
			expected: 0,
		},
		{
			name:     "no match - hex suffix too short",
			input:    "glsa_" + random32 + "_a1b2",
			expected: 0,
		},
		{
			name:     "no match - invalid hex suffix",
			input:    "glsa_" + random32 + "_ZZZZZZZZ",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "glsp_" + random32 + "_" + hexSuffix,
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
