package sendgrid

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
	assert.Equal(t, "sendgrid-api-key", d.ID())
	assert.Equal(t, "SendGrid API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic parts: 22-char and 43-char segments
	part1 := strings.Repeat("Ab", 11)       // 22 chars
	part2 := strings.Repeat("Cd", 21) + "E" // 43 chars
	syntheticKey := "SG." + part1 + "." + part2

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid SendGrid key",
			input:    syntheticKey,
			expected: 1,
			redacted: "SG.****" + syntheticKey[len(syntheticKey)-4:],
		},
		{
			name:     "key in env var",
			input:    `SENDGRID_API_KEY=` + syntheticKey,
			expected: 1,
		},
		{
			name:     "no match - missing second segment",
			input:    "SG." + part1,
			expected: 0,
		},
		{
			name:     "no match - short second segment",
			input:    "SG." + part1 + ".abc",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "XG." + part1 + "." + part2,
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
				assert.NotEqual(t, syntheticKey, findings[0].Redacted)
			}
		})
	}
}
