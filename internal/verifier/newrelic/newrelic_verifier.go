// Package newrelic provides a verifier for New Relic API keys.
// It uses the New Relic API GET /v2/users.json endpoint to check token validity.
package newrelic

import (
	"context"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "newrelic-api-key"

// defaultAPIURL is the base URL for the New Relic API.
const defaultAPIURL = "https://api.newrelic.com"

// Verifier checks whether a New Relic API key is active by calling the
// New Relic API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the New Relic API base URL (for testing).
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

// Verify checks if the detected New Relic API key is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "newrelic",
		Request: httpx.Request{
			URL:    apiURL + "/v2/users.json",
			Header: map[string]string{"Api-Key": token},
		},
		InactiveStatuses: []int{http.StatusUnauthorized, http.StatusForbidden},
		ActiveMessage:    "New Relic API key is active",
		InactiveMessage:  "New Relic API key is invalid or revoked",
	})
}
