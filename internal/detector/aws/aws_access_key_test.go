package aws

import (
	"context"
	"strings"
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccessKeyID_Metadata(t *testing.T) {
	d := &AccessKeyID{}
	assert.Equal(t, "aws-access-key-id", d.ID())
	assert.Equal(t, "AWS Access Key ID", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestAccessKeyID_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid AKIA key",
			input:    "AKIAIOSFODNN7EXAMPLE",
			expected: 1,
			redacted: "****MPLE",
		},
		{
			name:     "valid ASIA key (temporary credentials)",
			input:    "ASIAIOSFODNN7EXAMPLE",
			expected: 1,
			redacted: "****MPLE",
		},
		{
			name:     "key in config file",
			input:    "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			expected: 1,
		},
		{
			name:     "key in JSON",
			input:    `{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE"}`,
			expected: 1,
		},
		{
			name:     "no match - too short",
			input:    "AKIA1234567890",
			expected: 0,
		},
		{
			name:     "no match - plain text",
			input:    "this is just normal text",
			expected: 0,
		},
		{
			name:     "no match - lowercase",
			input:    "akiaiosfodnn7example",
			expected: 0,
		},
		{
			name:     "multiple keys in text",
			input:    "key1: AKIAIOSFODNN7EXAMPLE key2: ASIAIOSFODNN7EXAMPL2",
			expected: 2,
		},
		{
			name:     "key in large text",
			input:    strings.Repeat("a", 10000) + "AKIAIOSFODNN7EXAMPLE" + strings.Repeat("b", 10000),
			expected: 1,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
	}

	d := &AccessKeyID{}
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
