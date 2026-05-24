// Package digitalocean provides a verifier for DigitalOcean personal access tokens.
// It uses the DigitalOcean API GET /v2/account endpoint to check token validity.
package digitalocean

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "digitalocean-token"

// defaultAPIURL is the base URL for the DigitalOcean API.
const defaultAPIURL = "https://api.digitalocean.com"

// Verifier checks whether a DigitalOcean token is active by calling the
// DigitalOcean API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the DigitalOcean API base URL (for testing).
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

// Verify checks if the detected DigitalOcean token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "digitalocean",
		Request: httpx.Request{
			URL:    apiURL + "/v2/account",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "DigitalOcean token is active",
		InactiveMessage: "DigitalOcean token is invalid or revoked",
		Decode:          decodeAccount,
	})
}

// decodeAccount parses the DigitalOcean API response for a valid token.
func decodeAccount(body io.Reader) (map[string]string, string, error) {
	var response struct {
		Account struct {
			Email string `json:"email"`
		} `json:"account"`
	}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, "", err
	}
	return map[string]string{"email": response.Account.Email}, "", nil
}
