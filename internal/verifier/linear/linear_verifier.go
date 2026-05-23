// Package linear provides a verifier for Linear API keys.
// It uses the Linear GraphQL API to check key validity.
package linear

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "linear-api-key"

// defaultAPIURL is the base URL for the Linear GraphQL API.
const defaultAPIURL = "https://api.linear.app"

// viewerQuery requests the authenticated viewer to prove the key is usable.
var viewerQuery = []byte(`{"query":"{ viewer { id name } }"}`)

// Verifier checks whether a Linear API key is active by calling
// the Linear GraphQL API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Linear API base URL (for testing).
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

// Verify checks if the detected Linear API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "linear",
		Request: httpx.Request{
			Method: http.MethodPost,
			URL:    apiURL + "/graphql",
			Body:   viewerQuery,
			Header: map[string]string{
				"Authorization": "Bearer " + token,
				"Content-Type":  "application/json",
			},
		},
		ActiveMessage:   "Linear API key is active",
		InactiveMessage: "Linear API key is invalid or revoked",
		Decode:          decodeViewer,
	})
}

// decodeViewer reports the viewer name on success, downgrades to inactive when
// the GraphQL response carries errors, and treats a response missing both
// data.viewer and errors as a verify error.
func decodeViewer(body io.Reader) (map[string]string, string, error) {
	var resp struct {
		Data *struct {
			Viewer *struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		return nil, "", err
	}
	if len(resp.Errors) > 0 {
		return nil, "Linear API key is invalid or revoked", nil
	}
	if resp.Data != nil && resp.Data.Viewer != nil {
		return map[string]string{"name": resp.Data.Viewer.Name}, "", nil
	}
	return nil, "", errors.New("unexpected response format")
}
