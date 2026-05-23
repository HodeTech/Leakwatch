// Package bitbucket provides a verifier for Bitbucket app passwords.
// It uses the Bitbucket User API GET /2.0/user endpoint with Basic auth
// to check app password validity.
package bitbucket

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

const detectorID = "bitbucket-app-password"

// defaultAPIURL is the base URL for the Bitbucket API.
const defaultAPIURL = "https://api.bitbucket.org"

// Verifier checks whether a Bitbucket app password is active by calling the
// Bitbucket User API. It NEVER logs or persists raw password values.
type Verifier struct {
	// apiURL overrides the Bitbucket API base URL (for testing).
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

// Verify checks if the detected Bitbucket app password is valid/active.
// The Bitbucket username must be provided in raw.ExtraData["username"].
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	username := ""
	if raw.ExtraData != nil {
		username = raw.ExtraData["username"]
	}
	if username == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "Bitbucket username required",
		}
	}

	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)
	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "bitbucket",
		Request: httpx.Request{
			URL:           apiURL + "/2.0/user",
			BasicAuthUser: username,
			BasicAuthPass: token,
		},
		ActiveMessage:   "Bitbucket app password is active",
		InactiveMessage: "Bitbucket app password is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser reports the account display name as display_name.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"display_name": user.DisplayName}, "", nil
}
