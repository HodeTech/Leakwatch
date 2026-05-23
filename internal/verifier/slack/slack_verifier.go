// Package slack provides a verifier for Slack Bot/User tokens.
// It calls the Slack auth.test API endpoint to check token validity.
package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "slack-token"

// defaultAPIURL is the base URL for the Slack API.
const defaultAPIURL = "https://slack.com/api"

// Verifier checks whether a Slack token is active by calling the
// Slack auth.test endpoint. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the Slack API base URL (for testing).
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

// Verify checks if the detected Slack token is valid/active.
// Slack always answers auth.test with 200 and reports validity via the "ok"
// field, so no status code maps to inactive (InactiveStatuses is empty).
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "slack",
		Request: httpx.Request{
			Method: http.MethodPost,
			URL:    apiURL + "/auth.test",
			Header: map[string]string{
				"Authorization": "Bearer " + token,
				"Content-Type":  "application/json; charset=utf-8",
			},
		},
		InactiveStatuses: []int{},
		ActiveMessage:    "Slack token is active",
		Decode:           decodeAuthTest,
	})
}

// decodeAuthTest reports team and user on success and downgrades to inactive
// when the response body reports ok=false.
func decodeAuthTest(body io.Reader) (map[string]string, string, error) {
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Team  string `json:"team"`
		User  string `json:"user"`
		URL   string `json:"url"`
	}
	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return nil, "", err
	}
	if !result.OK {
		return nil, fmt.Sprintf("Slack token is invalid: %s", result.Error), nil
	}

	extra := map[string]string{}
	if result.Team != "" {
		extra["team"] = result.Team
	}
	if result.User != "" {
		extra["user"] = result.User
	}
	return extra, "", nil
}
