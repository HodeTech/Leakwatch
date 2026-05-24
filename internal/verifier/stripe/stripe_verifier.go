// Package stripe provides verifiers for Stripe API keys (live and test).
// It uses the Stripe Balance API GET /v1/balance endpoint with Basic auth
// to check key validity.
package stripe

import (
	"context"
	"fmt"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const (
	liveDetectorID = "stripe-api-key-live"
	testDetectorID = "stripe-api-key-test"
)

// defaultAPIURL is the base URL for the Stripe API.
const defaultAPIURL = "https://api.stripe.com"

// LiveKeyVerifier checks whether a Stripe live API key is active by calling
// the Stripe Balance API. It NEVER logs or persists raw key values.
type LiveKeyVerifier struct {
	// apiURL overrides the Stripe API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

// TestKeyVerifier checks whether a Stripe test API key is active.
// It uses the same endpoint and logic as LiveKeyVerifier.
type TestKeyVerifier struct {
	// apiURL overrides the Stripe API base URL (for testing).
	apiURL string
	// httpClient overrides the default HTTP client (for testing).
	httpClient *http.Client
}

func init() {
	verifier.Register(&LiveKeyVerifier{})
	verifier.Register(&TestKeyVerifier{})
}

// Type returns the detector ID this verifier handles.
func (v *LiveKeyVerifier) Type() string {
	return liveDetectorID
}

// Type returns the detector ID this verifier handles.
func (v *TestKeyVerifier) Type() string {
	return testDetectorID
}

// Verify checks if the detected Stripe live API key is valid/active.
func (v *LiveKeyVerifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	return verifyStripeKey(ctx, v.apiURL, v.httpClient, raw, "live")
}

// Verify checks if the detected Stripe test API key is valid/active.
func (v *TestKeyVerifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	return verifyStripeKey(ctx, v.apiURL, v.httpClient, raw, "test")
}

// verifyStripeKey performs the Stripe API key verification shared by both the
// live and test verifiers. Stripe authenticates the key as the Basic auth
// username (with an empty password) and reports validity by status code.
func verifyStripeKey(ctx context.Context, apiURL string, httpClient *http.Client, raw detector.RawFinding, keyType string) finding.VerificationResult {
	token := string(raw.Raw)
	resolved := httpx.BaseURL(apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, httpClient, token, httpx.TokenSpec{
		Name: "stripe",
		Request: httpx.Request{
			URL:           resolved + "/v1/balance",
			BasicAuthUser: token,
		},
		ActiveMessage:   fmt.Sprintf("Stripe %s API key is active", keyType),
		InactiveMessage: fmt.Sprintf("Stripe %s API key is invalid or revoked", keyType),
		ActiveExtra:     map[string]string{"key_type": keyType},
	})
}
