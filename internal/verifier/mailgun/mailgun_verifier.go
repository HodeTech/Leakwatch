// Package mailgun provides a verifier for Mailgun API keys.
// It uses the Mailgun API GET /v3/domains endpoint with Basic auth to check key validity.
package mailgun

import (
	"context"
	"net/http"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/httpx"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "mailgun-api-key"

// defaultAPIURL is the base URL for the Mailgun API.
const defaultAPIURL = "https://api.mailgun.net"

// Verifier checks whether a Mailgun API key is active by calling the
// Mailgun API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Mailgun API base URL (for testing).
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

// Verify checks if the detected Mailgun API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "mailgun",
		Request: httpx.Request{
			URL:           apiURL + "/v3/domains",
			BasicAuthUser: "api",
			BasicAuthPass: token,
		},
		ActiveMessage:   "Mailgun API key is active",
		InactiveMessage: "Mailgun API key is invalid or revoked",
	})
}
