// Package pagerduty provides a verifier for PagerDuty API keys.
// It uses the PagerDuty API GET /users/me endpoint to check key validity.
// Note: PagerDuty uses "Token token=" auth prefix instead of "Bearer".
package pagerduty

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "pagerduty-api-key"

// defaultAPIURL is the base URL for the PagerDuty API.
const defaultAPIURL = "https://api.pagerduty.com"

// Verifier checks whether a PagerDuty API key is active by calling the
// PagerDuty API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the PagerDuty API base URL (for testing).
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

// Verify checks if the detected PagerDuty API key is valid/active.
// Raw contains the key value.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	apiURL := v.apiURL
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/users/me", nil)
	if err != nil {
		slog.ErrorContext(ctx, "pagerduty verifier: failed to create request", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to create request: %v", err),
		}
	}
	req.Header.Set("Authorization", "Token token="+token)
	req.Header.Set("User-Agent", "leakwatch-verifier")

	client := v.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "pagerduty verifier: request failed", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("request failed: %v", err),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return handleActiveKey(ctx, resp.Body)
	case http.StatusUnauthorized:
		slog.DebugContext(ctx, "pagerduty verifier: API key is inactive")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "PagerDuty API key is invalid or revoked",
		}
	default:
		slog.ErrorContext(ctx, "pagerduty verifier: unexpected status code",
			slog.Int("status_code", resp.StatusCode),
		)
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
		}
	}
}

// handleActiveKey parses the PagerDuty API response for a valid key.
func handleActiveKey(ctx context.Context, body io.Reader) finding.VerificationResult {
	var resp struct {
		User struct {
			Name string `json:"name"`
		} `json:"user"`
	}

	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		slog.ErrorContext(ctx, "pagerduty verifier: failed to decode response", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "PagerDuty API key is active (could not parse user info)",
		}
	}

	extra := map[string]string{
		"user_name": resp.User.Name,
	}

	slog.InfoContext(ctx, "pagerduty verifier: API key is active",
		slog.String("user_name", resp.User.Name),
	)

	return finding.VerificationResult{
		Status:    finding.StatusVerifiedActive,
		Message:   "PagerDuty API key is active",
		ExtraData: extra,
	}
}
