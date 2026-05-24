// Package auth0 provides a verifier for Auth0 Management API tokens.
// It uses the Auth0 Management API GET /api/v2/ endpoint with Bearer auth
// to check token validity.
package auth0

import (
	"context"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "auth0-management-token"

// defaultAPIURL is the base URL for the Auth0 Management API.
const defaultAPIURL = "https://login.auth0.com"

// Verifier checks whether an Auth0 Management API token is active by calling
// the Auth0 Management API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Auth0 API base URL (for testing).
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

// Verify checks if the detected Auth0 Management API token is valid/active.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "auth0",
		Request: httpx.Request{
			URL:    apiURL + "/api/v2/",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Auth0 management token is active",
		InactiveMessage: "Auth0 management token is invalid or expired",
	})
}
