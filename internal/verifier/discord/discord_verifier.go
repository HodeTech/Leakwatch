// Package discord provides a verifier for Discord Bot tokens.
// It uses the Discord API GET /users/@me endpoint to check token validity.
package discord

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

const detectorID = "discord-bot-token"

// defaultAPIURL is the base URL for the Discord API.
const defaultAPIURL = "https://discord.com/api/v10"

// Verifier checks whether a Discord Bot token is active by calling the
// Discord API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Discord API base URL (for testing).
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

// Verify checks if the detected Discord Bot token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "discord",
		Request: httpx.Request{
			URL:    apiURL + "/users/@me",
			Header: map[string]string{"Authorization": "Bot " + token},
		},
		ActiveMessage:   "Discord Bot token is active",
		InactiveMessage: "Discord Bot token is invalid or revoked",
		Decode:          decodeUser,
	})
}

// decodeUser parses the Discord API response for a valid token.
func decodeUser(body io.Reader) (map[string]string, string, error) {
	var user struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		return nil, "", err
	}
	return map[string]string{"username": user.Username}, "", nil
}
