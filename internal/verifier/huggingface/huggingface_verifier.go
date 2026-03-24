// Package huggingface provides a verifier for HuggingFace tokens.
// It uses the HuggingFace API GET /api/whoami-v2 endpoint to check token validity.
package huggingface

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

const detectorID = "huggingface-token"

// defaultAPIURL is the base URL for the HuggingFace API.
const defaultAPIURL = "https://huggingface.co"

// Verifier checks whether a HuggingFace token is active by calling
// the HuggingFace API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the HuggingFace API base URL (for testing).
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

// Verify checks if the detected HuggingFace token is valid/active.
// Raw contains the token value.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/api/whoami-v2", nil)
	if err != nil {
		slog.ErrorContext(ctx, "huggingface verifier: failed to create request", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to create request: %v", err),
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "leakwatch-verifier")

	client := v.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "huggingface verifier: request failed", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("request failed: %v", err),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		return handleActiveToken(ctx, resp.Body)
	case http.StatusUnauthorized:
		slog.DebugContext(ctx, "huggingface verifier: token is inactive")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "HuggingFace token is invalid or revoked",
		}
	default:
		slog.ErrorContext(ctx, "huggingface verifier: unexpected status code",
			slog.Int("status_code", resp.StatusCode),
		)
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
		}
	}
}

// handleActiveToken parses the HuggingFace API response for a valid token.
func handleActiveToken(ctx context.Context, body io.Reader) finding.VerificationResult {
	var user struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(body).Decode(&user); err != nil {
		slog.ErrorContext(ctx, "huggingface verifier: failed to decode response", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "HuggingFace token is active (could not parse user info)",
		}
	}

	extra := map[string]string{
		"name": user.Name,
	}

	slog.InfoContext(ctx, "huggingface verifier: token is active",
		slog.String("name", user.Name),
	)

	return finding.VerificationResult{
		Status:    finding.StatusVerifiedActive,
		Message:   "HuggingFace token is active",
		ExtraData: extra,
	}
}
