// Package rubygems provides a verifier for RubyGems API keys.
// It uses the RubyGems API GET /api/v1/api_key.json endpoint to check key validity.
package rubygems

import (
	"context"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "rubygems-api-key"

// defaultAPIURL is the base URL for the RubyGems API.
const defaultAPIURL = "https://rubygems.org"

// Verifier checks whether a RubyGems API key is active by calling the
// RubyGems API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the RubyGems API base URL (for testing).
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

// Verify checks if the detected RubyGems API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "rubygems",
		Request: httpx.Request{
			URL:    apiURL + "/api/v1/api_key.json",
			Header: map[string]string{"Authorization": token},
		},
		ActiveMessage:   "RubyGems API key is active",
		InactiveMessage: "RubyGems API key is invalid or revoked",
	})
}
