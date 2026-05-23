// Package sentry provides a verifier for Sentry authentication tokens.
// It uses the auth-required Sentry API GET /api/0/organizations/ endpoint to
// check token validity. The API root (/api/0/) responds 200 without
// authentication, so it cannot distinguish a valid token from an invalid one
// and must not be used for verification.
package sentry

import (
	"context"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "sentry-token"

// defaultAPIURL is the base URL for the Sentry API.
const defaultAPIURL = "https://sentry.io"

// Verifier checks whether a Sentry token is active by calling the
// Sentry API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Sentry API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// Verify checks if the detected Sentry token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	// Use an auth-required endpoint: /api/0/ responds 200 without authentication
	// (false positive), whereas /api/0/organizations/ returns 401 for an invalid
	// token.
	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "sentry",
		Request: httpx.Request{
			URL:    apiURL + "/api/0/organizations/",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Sentry token is active",
		InactiveMessage: "Sentry token is invalid or revoked",
	})
}
