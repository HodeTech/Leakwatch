// Package dockerhub provides a verifier for Docker Hub Personal Access Tokens.
// It uses the Docker Hub API GET /v2/user/ endpoint to check token validity.
package dockerhub

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

const detectorID = "dockerhub-pat"

// defaultAPIURL is the base URL for the Docker Hub API.
const defaultAPIURL = "https://hub.docker.com"

// Verifier checks whether a Docker Hub PAT is active by calling the
// Docker Hub API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Docker Hub API base URL (for testing).
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

// Verify checks if the detected Docker Hub PAT is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "dockerhub",
		Request: httpx.Request{
			URL:    apiURL + "/v2/user/",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Docker Hub PAT is active",
		InactiveMessage: "Docker Hub PAT is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser parses the Docker Hub API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": user.Username}, "", nil
}
