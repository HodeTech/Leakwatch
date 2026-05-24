// Package pagerduty provides a verifier for PagerDuty API keys.
// It uses the PagerDuty API GET /users/me endpoint to check key validity.
// Note: PagerDuty uses "Token token=" auth prefix instead of "Bearer".
package pagerduty

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

const detectorID = "pagerduty-api-key"

// defaultAPIURL is the base URL for the PagerDuty API.
const defaultAPIURL = "https://api.pagerduty.com"

// Verifier checks whether a PagerDuty API key is active by calling the
// PagerDuty API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the PagerDuty API base URL (for testing).
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

// Verify checks if the detected PagerDuty API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "pagerduty",
		Request: httpx.Request{
			URL:    apiURL + "/users/me",
			Header: map[string]string{"Authorization": "Token token=" + token},
		},
		ActiveMessage:   "PagerDuty API key is active",
		InactiveMessage: "PagerDuty API key is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser reports the account name as user_name.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var resp struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return nil, "", err
	}
	return map[string]string{"user_name": resp.User.Name}, "", nil
}
