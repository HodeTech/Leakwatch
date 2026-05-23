// Package postmark provides a verifier for Postmark Server Tokens.
// It uses the Postmark API GET /server endpoint to check token validity.
package postmark

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

const detectorID = "postmark-server-token"

// defaultAPIURL is the base URL for the Postmark API.
const defaultAPIURL = "https://api.postmarkapp.com"

// Verifier checks whether a Postmark Server Token is active by calling the
// Postmark API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Postmark API base URL (for testing).
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

// Verify checks if the detected Postmark Server Token is valid/active.
// Raw contains the token value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "postmark",
		Request: httpx.Request{
			URL:    apiURL + "/server",
			Header: map[string]string{"X-Postmark-Server-Token": token},
		},
		ActiveMessage:   "Postmark server token is active",
		InactiveMessage: "Postmark server token is invalid or revoked",
		Decode:          decodeServer,
	})
}

// decodeServer reports the server name as server_name.
func decodeServer(body io.Reader) (map[string]string, string, error) {
	var server struct {
		Name string `json:"Name"`
	}
	if err := json.NewDecoder(body).Decode(&server); err != nil {
		return nil, "", err
	}
	return map[string]string{"server_name": server.Name}, "", nil
}
