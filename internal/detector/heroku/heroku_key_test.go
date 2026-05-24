package heroku

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "heroku-api-key", d.ID())
	assert.Equal(t, "Heroku API Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	syntheticUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
		rawUUID  string
	}{
		{
			name:     "HEROKU_API_KEY with equals sign",
			input:    "HEROKU_API_KEY=" + syntheticUUID,
			expected: 1,
			redacted: "****7890",
			rawUUID:  syntheticUUID,
		},
		{
			name:     "heroku_api_key with colon",
			input:    `heroku_api_key: "` + syntheticUUID + `"`,
			expected: 1,
			redacted: "****7890",
			rawUUID:  syntheticUUID,
		},
		{
			name:     "heroku with equals and quotes",
			input:    `heroku = '` + syntheticUUID + `'`,
			expected: 1,
			redacted: "****7890",
			rawUUID:  syntheticUUID,
		},
		{
			name:     "heroku with spaces around equals",
			input:    "HEROKU_API_KEY = " + syntheticUUID,
			expected: 1,
			redacted: "****7890",
		},
		{
			name:     "no match - bare UUID without context",
			input:    syntheticUUID,
			expected: 0,
		},
		{
			name:     "no match - wrong key name",
			input:    "AWS_KEY=" + syntheticUUID,
			expected: 0,
		},
		{
			name:     "no match - invalid UUID format",
			input:    "HEROKU_API_KEY=not-a-valid-uuid",
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
				if tt.rawUUID != "" {
					assert.Equal(t, tt.rawUUID, string(findings[0].Raw))
				}
			}
		})
	}
}
