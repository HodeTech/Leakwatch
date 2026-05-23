package terraform

import (
	"context"
	"strings"
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "terraform-cloud-token", d.ID())
	assert.Equal(t, "Terraform Cloud/Enterprise API Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Synthetic 14-char prefix and 67-char suffix
	prefix14 := strings.Repeat("aB1", 4) + "cD"
	suffix67 := strings.Repeat("xY2z", 16) + "aBc"
	suffix80 := strings.Repeat("xY2z", 20)

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token with 67 char suffix",
			input:    prefix14 + ".atlasv1." + suffix67,
			expected: 1,
			redacted: "****" + suffix67[len(suffix67)-4:],
		},
		{
			name:     "valid token with longer suffix",
			input:    prefix14 + ".atlasv1." + suffix80,
			expected: 1,
			redacted: "****" + suffix80[len(suffix80)-4:],
		},
		{
			name:     "token embedded in env var",
			input:    "TF_TOKEN=" + prefix14 + ".atlasv1." + suffix67,
			expected: 1,
		},
		{
			name:     "token embedded in config line",
			input:    `credentials "app.terraform.io" { token = "` + prefix14 + ".atlasv1." + suffix67 + `" }`,
			expected: 1,
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
			name:  "suffix too short",
			input: strings.Repeat("a", 14) + ".atlasv1." + strings.Repeat("b", 30),
		},
		{
			name:  "prefix too short",
			input: strings.Repeat("a", 5) + ".atlasv1." + strings.Repeat("b", 67),
		},
		{
			name:  "wrong separator",
			input: strings.Repeat("a", 14) + ".atlasv2." + strings.Repeat("b", 67),
		},
		{
			name:  "plain text",
			input: "this is just normal text with atlasv1 mentioned",
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
