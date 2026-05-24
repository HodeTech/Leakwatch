package slack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "slack-token", v.Type())
}

func TestVerify_EmptyToken_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte("")})
	assert.Equal(t, finding.StatusUnverified, result.Status)
}

func TestVerify_ValidToken_ReturnsActive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/auth.test", r.URL.Path)
		assert.Equal(t, "Bearer xoxb-test-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"team":"TestTeam","user":"testuser","url":"https://testteam.slack.com"}`))
	}))
	defer server.Close()

	v := &Verifier{apiURL: server.URL, httpClient: server.Client()}
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte("xoxb-test-token")})

	assert.Equal(t, finding.StatusVerifiedActive, result.Status)
	assert.Equal(t, "TestTeam", result.ExtraData["team"])
	assert.Equal(t, "testuser", result.ExtraData["user"])
}

func TestVerify_InvalidToken_ReturnsInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	}))
	defer server.Close()

	v := &Verifier{apiURL: server.URL, httpClient: server.Client()}
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte("xoxb-bad-token")})

	assert.Equal(t, finding.StatusVerifiedInactive, result.Status)
	assert.Contains(t, result.Message, "invalid_auth")
}

func TestVerify_ServerError_ReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	v := &Verifier{apiURL: server.URL, httpClient: server.Client()}
	result := v.Verify(context.Background(), detector.RawFinding{Raw: []byte("xoxb-test-token")})

	assert.Equal(t, finding.StatusVerifyError, result.Status)
	assert.Contains(t, result.Message, "500")
}
