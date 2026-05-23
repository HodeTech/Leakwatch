// Package pypi provides a verifier for PyPI API tokens.
// It uses the PyPI upload endpoint with Basic auth to check token validity.
// A 405 (Method Not Allowed) response indicates a valid token (authenticated
// but wrong HTTP method), while 401/403 indicates an invalid token.
package pypi

import (
	"context"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "pypi-api-token"

// defaultAPIURL is the base URL for the PyPI upload endpoint.
const defaultAPIURL = "https://upload.pypi.org"

// Verifier checks whether a PyPI API token is active by calling the
// PyPI upload endpoint. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the PyPI upload base URL (for testing).
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

// Verify checks if the detected PyPI API token is valid/active.
// Raw contains the token value. The upload endpoint answers an authenticated
// GET with 405 (wrong method), which is the positive signal; 401/403 means the
// token is rejected.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "pypi",
		Request: httpx.Request{
			URL:           apiURL + "/legacy/",
			BasicAuthUser: "__token__",
			BasicAuthPass: token,
		},
		ActiveStatuses:   []int{http.StatusMethodNotAllowed},
		InactiveStatuses: []int{http.StatusUnauthorized, http.StatusForbidden},
		ActiveMessage:    "PyPI API token is active",
		InactiveMessage:  "PyPI API token is invalid or revoked",
	})
}
