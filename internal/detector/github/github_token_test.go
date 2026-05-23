package github

import (
	"context"
	"strings"
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToken_Metadata(t *testing.T) {
	d := &Token{}
	assert.Equal(t, "github-token", d.ID())
	assert.Equal(t, "GitHub Personal Access Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestToken_Scan_MatchesValidTokens(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid ghp token",
			input:    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 1,
			redacted: "****ghij",
		},
		{
			// gho/ghu/ghs/ghr prefixes belong exclusively to the OAuth
			// detector now; the token detector must ignore them.
			name:     "ignores gho oauth token",
			input:    "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 0,
		},
		{
			name:     "ignores ghu oauth token",
			input:    "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 0,
		},
		{
			name:     "ignores ghs oauth token",
			input:    "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 0,
		},
		{
			name:     "ignores ghr oauth token",
			input:    "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 0,
		},
		{
			name:     "token in config file",
			input:    `GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij`,
			expected: 1,
		},
		{
			name:     "token in JSON",
			input:    `{"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}`,
			expected: 1,
		},
		{
			// Only the ghp_ token is a PAT; the ghs_ token is an OAuth token.
			name:     "multiple tokens only ghp counted",
			input:    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			expected: 1,
		},
		{
			name:     "token in large text",
			input:    strings.Repeat("x", 10000) + "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" + strings.Repeat("y", 10000),
			expected: 1,
		},
	}

	d := &Token{}
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

func TestToken_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "too short suffix",
			input: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
		},
		{
			name:  "wrong prefix",
			input: "ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
		},
		{
			name:  "plain text",
			input: "this is just normal text without tokens",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	d := &Token{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}
