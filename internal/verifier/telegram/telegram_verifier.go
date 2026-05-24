// Package telegram provides a verifier for Telegram Bot tokens.
// It uses the Telegram Bot API GET /bot{token}/getMe endpoint to check token validity.
package telegram

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

const detectorID = "telegram-bot-token"

// defaultAPIURL is the base URL for the Telegram Bot API.
const defaultAPIURL = "https://api.telegram.org"

// Verifier checks whether a Telegram Bot token is active by calling the
// Telegram Bot API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Telegram Bot API base URL (for testing).
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

// Verify checks if the detected Telegram Bot token is valid/active.
// The token is embedded in the request URL, so it is set as Redact to keep it
// out of any transport error text.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name:            "telegram",
		Request:         httpx.Request{URL: apiURL + "/bot" + token + "/getMe"},
		Redact:          token,
		ActiveMessage:   "Telegram Bot token is active",
		InactiveMessage: "Telegram Bot token is invalid or revoked",
		Decode:          decodeGetMe,
	})
}

// decodeGetMe reports the bot username on success and downgrades to inactive
// when the response body reports ok=false.
func decodeGetMe(body io.Reader) (map[string]string, string, error) {
	var response struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}
	if err := json.NewDecoder(body).Decode(&response); err != nil {
		return nil, "", err
	}
	if !response.OK {
		return nil, "Telegram Bot token returned ok=false", nil
	}
	return map[string]string{"username": response.Result.Username}, "", nil
}
