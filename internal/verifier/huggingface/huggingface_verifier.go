// Package huggingface provides a verifier for HuggingFace tokens.
// It uses the HuggingFace API GET /api/whoami-v2 endpoint to check token validity.
package huggingface

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

const detectorID = "huggingface-token"

// defaultAPIURL is the base URL for the HuggingFace API.
const defaultAPIURL = "https://huggingface.co"

// Verifier checks whether a HuggingFace token is active by calling
// the HuggingFace API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the HuggingFace API base URL (for testing).
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

// Verify checks if the detected HuggingFace token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "huggingface",
		Request: httpx.Request{
			URL:    apiURL + "/api/whoami-v2",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "HuggingFace token is active",
		InactiveMessage: "HuggingFace token is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser reports the account name as name.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"name": user.Name}, "", nil
}
