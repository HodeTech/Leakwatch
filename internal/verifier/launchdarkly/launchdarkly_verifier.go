// Package launchdarkly provides a verifier for LaunchDarkly SDK keys.
// It uses the LaunchDarkly API GET /api/v2/caller-identity endpoint to check key validity.
package launchdarkly

import (
	"context"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "launchdarkly-sdk-key"

// defaultAPIURL is the base URL for the LaunchDarkly API.
const defaultAPIURL = "https://app.launchdarkly.com"

// Verifier checks whether a LaunchDarkly SDK key is active by calling the
// LaunchDarkly API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the LaunchDarkly API base URL (for testing).
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

// Verify checks if the detected LaunchDarkly SDK key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "launchdarkly",
		Request: httpx.Request{
			URL:    apiURL + "/api/v2/caller-identity",
			Header: map[string]string{"Authorization": token},
		},
		ActiveMessage:   "LaunchDarkly SDK key is active",
		InactiveMessage: "LaunchDarkly SDK key is invalid or revoked",
	})
}
