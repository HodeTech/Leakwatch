// Package deepseek provides a verifier for DeepSeek API keys.
// It uses the DeepSeek API GET /models endpoint to check key validity.
// DeepSeek's API is OpenAI-compatible.
package deepseek

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

const detectorID = "deepseek-api-key"

// defaultAPIURL is the base URL for the DeepSeek API.
const defaultAPIURL = "https://api.deepseek.com"

// Verifier checks whether a DeepSeek API key is active by calling the
// DeepSeek API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the DeepSeek API base URL (for testing).
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

// Verify checks if the detected DeepSeek API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "deepseek",
		Request: httpx.Request{
			URL:    apiURL + "/models",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "DeepSeek API key is active",
		InactiveMessage: "DeepSeek API key is invalid or revoked",
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
