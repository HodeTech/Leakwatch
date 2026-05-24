// Package doppler provides a verifier for Doppler tokens.
// It uses the Doppler API GET /v3/me endpoint to check token validity.
package doppler

import (
	"context"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "doppler-token"

// defaultAPIURL is the base URL for the Doppler API.
const defaultAPIURL = "https://api.doppler.com"

// Verifier checks whether a Doppler token is active by calling the
// Doppler API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Doppler API base URL (for testing).
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

// Verify checks if the detected Doppler token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "doppler",
		Request: httpx.Request{
			URL:    apiURL + "/v3/me",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Doppler token is active",
		InactiveMessage: "Doppler token is invalid or revoked",
	})
}
