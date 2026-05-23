// Package notion provides a verifier for Notion integration tokens.
// It uses the Notion API GET /v1/users/me endpoint to check token validity.
package notion

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

const detectorID = "notion-token"

// defaultAPIURL is the base URL for the Notion API.
const defaultAPIURL = "https://api.notion.com"

// notionVersion is the required Notion-Version header value.
const notionVersion = "2022-06-28"

// Verifier checks whether a Notion integration token is active by calling the
// Notion API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Notion API base URL (for testing).
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

// Verify checks if the detected Notion token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "notion",
		Request: httpx.Request{
			URL: apiURL + "/v1/users/me",
			Header: map[string]string{
				"Authorization":  "Bearer " + token,
				"Notion-Version": notionVersion,
			},
		},
		ActiveMessage:   "Notion token is active",
		InactiveMessage: "Notion token is invalid or revoked",
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
