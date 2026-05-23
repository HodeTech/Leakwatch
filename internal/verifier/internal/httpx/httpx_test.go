package httpx

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactError_ReplacesSecret(t *testing.T) {
	// fakeSecret is a non-secret placeholder used only to prove redaction.
	const fakeSecret = "FAKEtoken1234567890"

	tests := []struct {
		name        string
		err         error
		secret      string
		wantContain string
		wantAbsent  string
	}{
		{
			name:        "secret embedded in url error is redacted",
			err:         errors.New(`Get "https://api.example.com/bot` + fakeSecret + `/getMe": dial tcp: lookup failed`),
			secret:      fakeSecret,
			wantContain: "[REDACTED]",
			wantAbsent:  fakeSecret,
		},
		{
			name:        "secret appearing multiple times is fully redacted",
			err:         errors.New(fakeSecret + " then again " + fakeSecret),
			secret:      fakeSecret,
			wantContain: "[REDACTED] then again [REDACTED]",
			wantAbsent:  fakeSecret,
		},
		{
			name:        "no secret present leaves message intact",
			err:         errors.New("dial tcp: connection refused"),
			secret:      fakeSecret,
			wantContain: "dial tcp: connection refused",
			wantAbsent:  fakeSecret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactError(tt.err, tt.secret)
			assert.Contains(t, got, tt.wantContain)
			assert.NotContains(t, got, tt.wantAbsent)
		})
	}
}

func TestRedactError_EmptySecret_ReturnsOriginal(t *testing.T) {
	err := errors.New("some transport error")
	assert.Equal(t, "some transport error", RedactError(err, ""))
}

func TestRedactError_NilError_ReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", RedactError(nil, "anything"))
}
