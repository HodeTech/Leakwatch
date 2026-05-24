// Package anthropic provides a verifier for Anthropic API keys.
// It uses the Anthropic API GET /v1/models endpoint to check key validity.
package anthropic

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "anthropic-api-key"

// defaultAPIURL is the base URL for the Anthropic API.
const defaultAPIURL = "https://api.anthropic.com"

// Verifier checks whether an Anthropic API key is active by calling the
// Anthropic API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Anthropic API base URL (for testing).
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

// Verify checks if the detected Anthropic API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "anthropic",
		Request: httpx.Request{
			URL: apiURL + "/v1/models",
			Header: map[string]string{
				"x-api-key":         token,
				"anthropic-version": "2023-06-01",
			},
		},
		ActiveMessage:   "Anthropic API key is active",
		InactiveMessage: "Anthropic API key is invalid or revoked",
		Decode:          decodeModels,
	})
}

// decodeModels reports the number of models the key can list as model_count.
func decodeModels(body io.Reader) (map[string]string, string, error) {
	var models struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(body).Decode(&models); err != nil {
		return nil, "", err
	}
	return map[string]string{"model_count": fmt.Sprintf("%d", len(models.Data))}, "", nil
}
