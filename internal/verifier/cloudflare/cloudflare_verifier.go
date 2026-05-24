// Package cloudflare provides a verifier for Cloudflare API tokens.
// It uses the Cloudflare API GET /client/v4/user/tokens/verify endpoint to check token validity.
package cloudflare

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

const detectorID = "cloudflare-api-token"

// defaultAPIURL is the base URL for the Cloudflare API.
const defaultAPIURL = "https://api.cloudflare.com"

// Verifier checks whether a Cloudflare API token is active by calling the
// Cloudflare API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Cloudflare API base URL (for testing).
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

// Verify checks if the detected Cloudflare API token is valid/active.
// Raw contains the token value. A 200 response may still indicate an inactive
// token when the response body reports success=false.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "cloudflare",
		Request: httpx.Request{
			URL:    apiURL + "/client/v4/user/tokens/verify",
			Header: map[string]string{"Authorization": "Bearer " + token},
		},
		ActiveMessage:   "Cloudflare API token is active",
		InactiveMessage: "Cloudflare API token is invalid or revoked",
		Decode:          decodeVerify,
	})
}

// decodeVerify downgrades a 200 response to inactive when success=false,
// surfacing the first API error message when present.
func decodeVerify(body io.Reader) (map[string]string, string, error) {
	var response struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, "", err
	}
	if !response.Success {
		msg := "Cloudflare API token is inactive"
		if len(response.Errors) > 0 {
			msg = fmt.Sprintf("Cloudflare API token is inactive: %s", response.Errors[0].Message)
		}
		return nil, msg, nil
	}
	return nil, "", nil
}
