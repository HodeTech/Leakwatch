// Package terraform provides a verifier for Terraform Cloud API tokens.
// It uses the Terraform Cloud API GET /api/v2/account/details endpoint to check token validity.
package terraform

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

const detectorID = "terraform-cloud-token"

// defaultAPIURL is the base URL for the Terraform Cloud API.
const defaultAPIURL = "https://app.terraform.io"

// Verifier checks whether a Terraform Cloud API token is active by calling the
// Terraform Cloud API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Terraform Cloud API base URL (for testing).
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

// Verify checks if the detected Terraform Cloud API token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "terraform",
		Request: httpx.Request{
			URL:    apiURL + "/api/v2/account/details",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Terraform Cloud API token is active",
		InactiveMessage: "Terraform Cloud API token is invalid or revoked",
		Decode:          decodeAccount,
	})
}

// decodeAccount reports the account name as username.
func decodeAccount(body io.Reader) (map[string]string, string, error) {
	var account struct {
		Data struct {
			Attributes struct {
				Username string `json:"username"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(body).Decode(&account); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": account.Data.Attributes.Username}, "", nil
}
