package circleci

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
	assert.Equal(t, "circleci-token", d.ID())
	assert.Equal(t, "CircleCI Personal API Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// Synthetic 50-char suffix
	suffix50 := strings.Repeat("Abc1D", 10)
	validToken := "CCIPAT_" + suffix50

	// Longer suffix (75 chars)
	suffix75 := strings.Repeat("Abc1D", 15)
	longerToken := "CCIPAT_" + suffix75

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 50 char suffix",
			input:    validToken,
			expected: 1,
			redacted: "CCIPAT_****" + validToken[len(validToken)-4:],
		},
		{
			name:     "valid token with longer suffix",
			input:    longerToken,
			expected: 1,
			redacted: "CCIPAT_****" + longerToken[len(longerToken)-4:],
		},
		{
			name:     "token embedded in config",
			input:    `CIRCLECI_TOKEN=CCIPAT_` + suffix50,
			expected: 1,
		},
		{
			name:     "no match - suffix too short",
			input:    "CCIPAT_abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "CCAPAT_" + suffix50,
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
