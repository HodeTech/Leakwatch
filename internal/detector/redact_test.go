package detector

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedact_LongValue_RevealsOnlyLastFour(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "typical secret reveals last four",
			value: "AKIAIOSFODNN7EXAMPLE",
			want:  "****MPLE",
		},
		{
			name:  "value with provider prefix hides leading body",
			value: "sk-ant-Abc1234567890XYZ",
			want:  "****0XYZ",
		},
		{
			name:  "exactly five characters reveals last four",
			value: "abcde",
			want:  "****bcde",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.value)
			assert.Equal(t, tt.want, got)
			// The first body character must never appear at the front of the
			// redacted output.
			assert.True(t, strings.HasPrefix(got, redactMask))
			assert.NotContains(t, got, tt.value[:1]+tt.value[1:len(tt.value)-revealedSuffixLen])
		})
	}
}

func TestRedact_ShortValue_FullyMasked(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "one char", value: "a"},
		{name: "exactly suffix length", value: "abcd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, redactMask, Redact(tt.value))
		})
	}
}

func TestRedactBytes_MatchesRedact(t *testing.T) {
	values := []string{"", "abc", "abcd", "abcde", "AKIAIOSFODNN7EXAMPLE"}
	for _, v := range values {
		assert.Equal(t, Redact(v), RedactBytes([]byte(v)))
	}
}
