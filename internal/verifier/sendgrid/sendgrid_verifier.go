// Package sendgrid provides a verifier for SendGrid API keys.
// It uses the SendGrid API GET /v3/user/profile endpoint to check key validity.
package sendgrid

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

const detectorID = "sendgrid-api-key"

// defaultAPIURL is the base URL for the SendGrid API.
const defaultAPIURL = "https://api.sendgrid.com"

// Verifier checks whether a SendGrid API key is active by calling the
// SendGrid API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the SendGrid API base URL (for testing).
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

// Verify checks if the detected SendGrid API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "sendgrid",
		Request: httpx.Request{
			URL:    apiURL + "/v3/user/profile",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		InactiveStatuses: []int{http.StatusUnauthorized, http.StatusForbidden},
		ActiveMessage:    "SendGrid API key is active",
		InactiveMessage:  "SendGrid API key is invalid or revoked",
		Decode:           decodeProfile,
	})
}

// decodeProfile reports the account name as username.
func decodeProfile(body io.Reader) (map[string]string, string, error) {
	var profile struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(body).Decode(&profile); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": profile.Username}, "", nil
}
