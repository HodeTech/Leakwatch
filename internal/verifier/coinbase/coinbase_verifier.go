// Package coinbase provides a verifier for Coinbase API keys.
// It uses the Coinbase API GET /v2/user endpoint to check key validity.
package coinbase

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "coinbase-api-key"

// defaultAPIURL is the base URL for the Coinbase API.
const defaultAPIURL = "https://api.coinbase.com"

// Verifier checks whether a Coinbase API key is active by calling the
// Coinbase API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Coinbase API base URL (for testing).
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

// Verify checks if the detected Coinbase API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "coinbase",
		Request: httpx.Request{
			URL:    apiURL + "/v2/user",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Coinbase API key is active",
		InactiveMessage: "Coinbase API key is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser parses the Coinbase API response for a valid key.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Data struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"name": user.Data.Name}, "", nil
}
