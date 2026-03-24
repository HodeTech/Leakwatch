// Package linear provides a verifier for Linear API keys.
// It uses the Linear GraphQL API to check key validity.
package linear

import (
	"bytes"
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

const detectorID = "linear-api-key"

// defaultAPIURL is the base URL for the Linear GraphQL API.
const defaultAPIURL = "https://api.linear.app"

// Verifier checks whether a Linear API key is active by calling
// the Linear GraphQL API. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Linear API base URL (for testing).
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

// Verify checks if the detected Linear API key is valid/active.
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

	body := []byte(`{"query":"{ viewer { id name } }"}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		slog.ErrorContext(ctx, "linear verifier: failed to create request", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to create request: %v", err),
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "leakwatch-verifier")

	client := v.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "linear verifier: request failed", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("request failed: %v", err),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return handleOKResponse(ctx, resp.Body)
	case http.StatusUnauthorized:
		slog.DebugContext(ctx, "linear verifier: API key is inactive")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "Linear API key is invalid or revoked",
		}
	default:
		slog.ErrorContext(ctx, "linear verifier: unexpected status code",
			slog.Int("status_code", resp.StatusCode),
		)
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
		}
	}
}

// handleOKResponse parses the Linear GraphQL response and distinguishes
// between a valid key (data.viewer present) and an error response.
func handleOKResponse(ctx context.Context, body io.Reader) finding.VerificationResult {
	var resp struct {
		Data *struct {
			Viewer *struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		slog.ErrorContext(ctx, "linear verifier: failed to decode response", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to decode response: %v", err),
		}
	}

	if len(resp.Errors) > 0 {
		slog.DebugContext(ctx, "linear verifier: API key returned errors",
			slog.String("error", resp.Errors[0].Message),
		)
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "Linear API key is invalid or revoked",
		}
	}

	if resp.Data != nil && resp.Data.Viewer != nil {
		extra := map[string]string{
			"name": resp.Data.Viewer.Name,
		}

		slog.InfoContext(ctx, "linear verifier: API key is active",
			slog.String("name", resp.Data.Viewer.Name),
		)

		return finding.VerificationResult{
			Status:    finding.StatusVerifiedActive,
			Message:   "Linear API key is active",
			ExtraData: extra,
		}
	}

	return finding.VerificationResult{
		Status:  finding.StatusVerifyError,
		Message: "unexpected response format",
	}
}
