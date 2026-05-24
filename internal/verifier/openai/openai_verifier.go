// Package openai provides a verifier for OpenAI API keys.
// It uses the OpenAI API GET /v1/models endpoint to check key validity.
package openai

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

const detectorID = "openai-api-key"

// defaultAPIURL is the base URL for the OpenAI API.
const defaultAPIURL = "https://api.openai.com"

// Verifier checks whether an OpenAI API key is active by calling the
// OpenAI API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the OpenAI API base URL (for testing).
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

// Verify checks if the detected OpenAI API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "openai",
		Request: httpx.Request{
			URL:    apiURL + "/v1/models",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "OpenAI API key is active",
		InactiveMessage: "OpenAI API key is invalid or revoked",
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
