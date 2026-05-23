// Package databricks provides a verifier for Databricks personal access tokens.
// It uses the Databricks SCIM API GET /api/2.0/preview/scim/v2/Me endpoint to check token validity.
package databricks

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

const detectorID = "databricks-token"

// defaultAPIURL is the base URL for the Databricks accounts API.
const defaultAPIURL = "https://accounts.cloud.databricks.com"

// Verifier checks whether a Databricks personal access token is active by calling
// the Databricks SCIM API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Databricks API base URL (for testing).
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

// Verify checks if the detected Databricks token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "databricks",
		Request: httpx.Request{
			URL:    apiURL + "/api/2.0/preview/scim/v2/Me",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Databricks token is active",
		InactiveMessage: "Databricks token is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser parses the Databricks SCIM API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		UserName string `json:"userName"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"userName": user.UserName}, "", nil
}
