package doppler

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
	assert.Equal(t, "doppler-token", d.ID())
	assert.Equal(t, "Doppler Service Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// 40-char alphanumeric suffix
	suffix40 := strings.Repeat("AbCd1234", 5)
	// 50-char suffix (longer valid token)
	suffix50 := strings.Repeat("AbCd1234", 6) + "Xy"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid doppler token with 40 char suffix",
			input:    "dp.st." + suffix40,
			expected: 1,
			redacted: "dp.st.****1234",
		},
		{
			name:     "valid doppler token with longer suffix",
			input:    "dp.st." + suffix50,
			expected: 1,
			redacted: "dp.st.****34Xy",
		},
		{
			name:     "token with underscores and hyphens",
			input:    "dp.st." + strings.Repeat("Ab_d-234", 5),
			expected: 1,
		},
		{
			name:     "token in env var",
			input:    `DOPPLER_TOKEN="dp.st.` + suffix40 + `"`,
			expected: 1,
		},
		{
			name:     "token in large text",
			input:    strings.Repeat("x", 10000) + "dp.st." + suffix40 + strings.Repeat("y", 10000),
			expected: 1,
		},
		{
			name:     "multiple tokens",
			input:    "dp.st." + suffix40 + " dp.st." + suffix50,
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
			input: "dp.xx." + strings.Repeat("AbCd1234", 5),
		},
		{
			name:  "too short suffix",
			input: "dp.st.abc123",
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
