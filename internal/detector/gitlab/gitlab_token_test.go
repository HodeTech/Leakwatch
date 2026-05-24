package gitlab

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "gitlab-pat", d.ID())
	assert.Equal(t, "GitLab Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 20-char token body
	tokenBody := "abcDEF1234567890xyzW"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid GitLab PAT",
			input:    "glpat-" + tokenBody,
			expected: 1,
			redacted: "glpat-****xyzW",
		},
		{
			name:     "key in config file",
			input:    `GITLAB_TOKEN=glpat-` + tokenBody,
			expected: 1,
		},
		{
			name:     "no match - too short",
			input:    "glpat-abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "ghpat-" + tokenBody,
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
				assert.NotContains(t, findings[0].Redacted, tokenBody)
			}
		})
	}
}
