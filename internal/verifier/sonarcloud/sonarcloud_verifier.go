// Package sonarcloud provides a verifier for SonarCloud tokens.
// It uses the SonarCloud API GET /api/authentication/validate endpoint to check token validity.
package sonarcloud

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

const detectorID = "sonarcloud-token"

// defaultAPIURL is the base URL for the SonarCloud API.
const defaultAPIURL = "https://sonarcloud.io"

// inactiveMessage is shared by the 401 path and the 200-with-valid=false path.
const inactiveMessage = "SonarCloud token is invalid or revoked"

// Verifier checks whether a SonarCloud token is active by calling the
// SonarCloud API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the SonarCloud API base URL (for testing).
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

// Verify checks if the detected SonarCloud token is valid/active.
// Raw contains the token value. SonarCloud authenticates the token as the Basic
// auth username (with an empty password) and reports validity in the body.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "sonarcloud",
		Request: httpx.Request{
			URL:           apiURL + "/api/authentication/validate",
			BasicAuthUser: token,
		},
		ActiveMessage:   "SonarCloud token is active",
		InactiveMessage: inactiveMessage,
		Decode:          decodeValidation,
	})
}

// decodeValidation downgrades a 200 response to inactive when valid=false.
func decodeValidation(body io.Reader) (map[string]string, string, error) {
	var validation struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(body).Decode(&validation); err != nil {
		return nil, "", err
	}
	if !validation.Valid {
		return nil, inactiveMessage, nil
	}
	return nil, "", nil
}
