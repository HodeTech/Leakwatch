// Package twilio provides a verifier for Twilio API keys.
// It uses the Twilio Accounts API GET /2010-04-01/Accounts.json endpoint
// with Basic auth to check key validity.
package twilio

import (
	"context"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "twilio-api-key"

// defaultAPIURL is the base URL for the Twilio API.
const defaultAPIURL = "https://api.twilio.com"

// Verifier checks whether a Twilio API key is active by calling the
// Twilio Accounts API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Twilio API base URL (for testing).
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

// Verify checks if the detected Twilio API key is valid/active.
// The Account SID must be provided in raw.ExtraData["account_sid"].
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	accountSID := ""
	if raw.ExtraData != nil {
		accountSID = raw.ExtraData["account_sid"]
	}
	if accountSID == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "Account SID required",
		}
	}

	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)
	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "twilio",
		Request: httpx.Request{
			URL:           apiURL + "/2010-04-01/Accounts.json",
			BasicAuthUser: accountSID,
			BasicAuthPass: token,
		},
		ActiveMessage:   "Twilio API key is active",
		InactiveMessage: "Twilio API key is invalid or revoked",
	})
}
