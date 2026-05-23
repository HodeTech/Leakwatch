// Package heroku provides a verifier for Heroku API keys.
// It uses the Heroku API GET /account endpoint to check token validity.
package heroku

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

const detectorID = "heroku-api-key"

// defaultAPIURL is the base URL for the Heroku API.
const defaultAPIURL = "https://api.heroku.com"

// Verifier checks whether a Heroku API key is active by calling the
// Heroku API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Heroku API base URL (for testing).
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

// Verify checks if the detected Heroku API key is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "heroku",
		Request: httpx.Request{
			URL: apiURL + "/account",
			Header: map[string]string{
				"Authorization": "Bearer " + token,
				"Accept":        "application/vnd.heroku+json; version=3",
			},
		},
		ActiveMessage:   "Heroku API key is active",
		InactiveMessage: "Heroku API key is invalid or revoked",
		Decode:          decodeAccount,
	})
}

// decodeAccount parses the Heroku API response for a valid token.
func decodeAccount(body io.Reader) (map[string]string, string, error) {
	var account struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(body).Decode(&account); err != nil {
		return nil, "", err
	}
	return map[string]string{"email": account.Email}, "", nil
}
