// Package airtable provides a verifier for Airtable personal access tokens.
// It uses the Airtable API GET /v0/meta/whoami endpoint to check token validity.
package airtable

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

const detectorID = "airtable-pat"

// defaultAPIURL is the base URL for the Airtable API.
const defaultAPIURL = "https://api.airtable.com"

// Verifier checks whether an Airtable personal access token is active by calling
// the Airtable API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Airtable API base URL (for testing).
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

// Verify checks if the detected Airtable personal access token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "airtable",
		Request: httpx.Request{
			URL:    apiURL + "/v0/meta/whoami",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Airtable token is active",
		InactiveMessage: "Airtable token is invalid or revoked",
		Decode:          decodeWhoami,
	})
}

// decodeWhoami reports the authenticated user id as id.
func decodeWhoami(body io.Reader) (map[string]string, string, error) {
	var user struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"id": user.ID}, "", nil
}
