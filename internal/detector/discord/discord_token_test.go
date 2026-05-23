package discord

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
	assert.Equal(t, "discord-bot-token", d.ID())
	assert.Equal(t, "Discord Bot Token", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.Empty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidTokens(t *testing.T) {
	// Build synthetic token parts:
	// First segment: M + 23 chars = 24 chars total
	seg1 := "M" + strings.Repeat("Aa1b", 5) + "Xyz"
	// Dot + 6 chars
	seg2 := "Ab1Cd2"
	// Dot + 27 chars
	seg3 := strings.Repeat("Abc1", 6) + "XyZ"

	syntheticToken := seg1 + "." + seg2 + "." + seg3

	// Longer third segment (40 chars)
	seg3Long := strings.Repeat("Abc1", 10)
	syntheticTokenLong := seg1 + "." + seg2 + "." + seg3Long

	// Token starting with N
	seg1N := "N" + strings.Repeat("Aa1b", 5) + "Xyz"
	syntheticTokenN := seg1N + "." + seg2 + "." + seg3

	// Token starting with O
	seg1O := "O" + strings.Repeat("Aa1b", 5) + "Xyz"
	syntheticTokenO := seg1O + "." + seg2 + "." + seg3

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "valid token starting with M",
			input:    syntheticToken,
			expected: 1,
			redacted: "****" + syntheticToken[len(syntheticToken)-4:],
		},
		{
			name:     "valid token starting with N",
			input:    syntheticTokenN,
			expected: 1,
			redacted: "****" + syntheticTokenN[len(syntheticTokenN)-4:],
		},
		{
			name:     "valid token starting with O",
			input:    syntheticTokenO,
			expected: 1,
			redacted: "****" + syntheticTokenO[len(syntheticTokenO)-4:],
		},
		{
			name:     "valid token with longer third segment",
			input:    syntheticTokenLong,
			expected: 1,
			redacted: "****" + syntheticTokenLong[len(syntheticTokenLong)-4:],
		},
		{
			name:     "token embedded in config line",
			input:    "DISCORD_TOKEN=" + syntheticToken,
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

func TestDetector_Scan_RejectsInvalidTokens(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "wrong start letter A",
			input: "A" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27),
		},
		{
			name:  "first segment too short",
			input: "M" + strings.Repeat("a", 10) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27),
		},
		{
			name:  "second segment too short",
			input: "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 3) + "." + strings.Repeat("c", 27),
		},
		{
			name:  "third segment too short",
			input: "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 10),
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

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}
