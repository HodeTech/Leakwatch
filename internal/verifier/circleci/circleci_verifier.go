// Package circleci provides a verifier for CircleCI API tokens.
// It uses the CircleCI API GET /api/v2/me endpoint to check token validity.
package circleci

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

const detectorID = "circleci-token"

// defaultAPIURL is the base URL for the CircleCI API.
const defaultAPIURL = "https://circleci.com"

// Verifier checks whether a CircleCI API token is active by calling
// the CircleCI API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the CircleCI API base URL (for testing).
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

// Verify checks if the detected CircleCI API token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "circleci",
		Request: httpx.Request{
			URL:    apiURL + "/api/v2/me",
			Header: map[string]string{"Circle-Token": token},
		},
		ActiveMessage:   "CircleCI token is active",
		InactiveMessage: "CircleCI token is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser parses the CircleCI API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"name": user.Name}, "", nil
}
