// Package npm provides a verifier for npm authentication tokens.
// It uses the npm registry GET /-/whoami endpoint to check token validity.
package npm

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

const detectorID = "npm-token"

// defaultAPIURL is the base URL for the npm registry.
const defaultAPIURL = "https://registry.npmjs.org"

// Verifier checks whether an npm token is active by calling the
// npm registry. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the npm registry base URL (for testing).
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

// Verify checks if the detected npm token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "npm",
		Request: httpx.Request{
			URL:    apiURL + "/-/whoami",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "npm token is active",
		InactiveMessage: "npm token is invalid or revoked",
		Decode:          decodeWhoami,
	})
}

// decodeWhoami reports the account name as username.
func decodeWhoami(body io.Reader) (map[string]string, string, error) {
	var whoami struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(body).Decode(&whoami); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": whoami.Username}, "", nil
}
