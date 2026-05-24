package dockerhub

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
	assert.Equal(t, "dockerhub-pat", d.ID())
	assert.Equal(t, "Docker Hub Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 27-char suffix
	suffix27 := strings.Repeat("AbcD1", 5) + "Xy"
	// synthetic 40-char suffix (longer valid token)
	suffix40 := strings.Repeat("AbcD1", 8)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 27 char suffix",
			input:    "dckr_pat_" + suffix27,
			expected: 1,
			redacted: "dckr_pat_****" + suffix27[len(suffix27)-4:],
		},
		{
			name:     "valid token with longer suffix",
			input:    "dckr_pat_" + suffix40,
			expected: 1,
			redacted: "dckr_pat_****" + suffix40[len(suffix40)-4:],
		},
		{
			name:     "token embedded in docker config",
			input:    `"token": "dckr_pat_` + suffix27 + `"`,
			expected: 1,
		},
		{
			name:     "no match - too short suffix",
			input:    "dckr_pat_abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "ghp_" + suffix27,
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
