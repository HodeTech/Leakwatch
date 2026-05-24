package huggingface

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
	assert.Equal(t, "huggingface-token", d.ID())
	assert.Equal(t, "Hugging Face API Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchAndReject(t *testing.T) {
	// synthetic 34-char alphanumeric suffix
	suffix34 := strings.Repeat("Abcd1234", 4) + "Xy"
	// synthetic 40-char suffix (valid but longer)
	suffix40 := strings.Repeat("Abcd1234", 5)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 34 char suffix",
			input:    "hf_" + suffix34,
			expected: 1,
			redacted: "hf_****34Xy",
		},
		{
			name:     "valid token with longer suffix",
			input:    "hf_" + suffix40,
			expected: 1,
			redacted: "hf_****1234",
		},
		{
			name:     "token embedded in config",
			input:    `HUGGINGFACE_TOKEN=hf_` + suffix34,
			expected: 1,
			redacted: "hf_****34Xy",
		},
		{
			name:     "multiple tokens",
			input:    "hf_" + suffix34 + " and hf_" + suffix40,
			expected: 2,
		},
		{
			name:     "no match - too short suffix",
			input:    "hf_abc123",
			expected: 0,
		},
		{
			name:     "no match - wrong prefix",
			input:    "xf_" + suffix34,
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
