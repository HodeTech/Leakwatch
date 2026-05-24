package sonarcloud

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
	assert.Equal(t, "sonarcloud-token", d.ID())
	assert.Equal(t, "SonarCloud/SonarQube Token", d.Description())
	assert.Equal(t, finding.SeverityHigh, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// 40-char hex suffix
	hex40 := strings.Repeat("abcdef01", 5)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid sonarcloud token",
			input:    "sqp_" + hex40,
			expected: 1,
			redacted: "sqp_****ef01",
		},
		{
			name:     "token in env var",
			input:    `SONAR_TOKEN="sqp_` + hex40 + `"`,
			expected: 1,
			redacted: "sqp_****ef01",
		},
		{
			name:     "token in large text",
			input:    strings.Repeat("x", 10000) + "sqp_" + hex40 + strings.Repeat("y", 10000),
			expected: 1,
		},
		{
			name:     "multiple tokens",
			input:    "sqp_" + hex40 + " sqp_" + strings.Repeat("12345678", 5),
			expected: 2,
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

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "wrong prefix",
			input: "sqx_" + strings.Repeat("abcdef01", 5),
		},
		{
			name:  "too short hex portion",
			input: "sqp_abcdef0123456789",
		},
		{
			name:  "non-hex characters",
			input: "sqp_" + strings.Repeat("ghijklmn", 5),
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
