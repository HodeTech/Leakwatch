// Package vercel provides a verifier for Vercel authentication tokens.
// It uses the Vercel API GET /v2/user endpoint to check token validity.
package vercel

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

const detectorID = "vercel-token"

// defaultAPIURL is the base URL for the Vercel API.
const defaultAPIURL = "https://api.vercel.com"

// Verifier checks whether a Vercel token is active by calling the
// Vercel API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Vercel API base URL (for testing).
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

// Verify checks if the detected Vercel token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "vercel",
		Request: httpx.Request{
			URL:    apiURL + "/v2/user",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		InactiveStatuses: []int{http.StatusUnauthorized, http.StatusForbidden},
		ActiveMessage:    "Vercel token is active",
		InactiveMessage:  "Vercel token is invalid or revoked",
		Decode:           decodeUser,
	})
}

// decodeUser reports the account name as username.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": user.User.Username}, "", nil
}
