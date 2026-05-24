package npm

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
	assert.Equal(t, "npm-token", d.ID())
	assert.Equal(t, "NPM Access Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 36-char alphanumeric suffix
	suffix36 := strings.Repeat("Abc1", 9) // 36 chars

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid NPM token",
			input:    "npm_" + suffix36,
			expected: 1,
			redacted: "npm_****Abc1",
		},
		{
			name:     "token in npmrc file",
			input:    `//registry.npmjs.org/:_authToken=npm_` + suffix36,
			expected: 1,
		},
		{
			name:     "no match - too short",
			input:    "npm_abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "npa_" + suffix36,
			expected: 0,
		},
		{
			name:     "no match - contains special chars",
			input:    "npm_abc!@#$%^&*()_+=-{}[]abc123456789",
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
				assert.NotContains(t, findings[0].Redacted, suffix36)
			}
		})
	}
}
