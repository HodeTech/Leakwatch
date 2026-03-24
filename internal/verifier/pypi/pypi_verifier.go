// Package pypi provides a verifier for PyPI API tokens.
// It uses the PyPI upload endpoint with Basic auth to check token validity.
// A 405 (Method Not Allowed) response indicates a valid token (authenticated
// but wrong HTTP method), while 401/403 indicates an invalid token.
package pypi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "pypi-api-token"

// defaultAPIURL is the base URL for the PyPI upload endpoint.
const defaultAPIURL = "https://upload.pypi.org"

// Verifier checks whether a PyPI API token is active by calling the
// PyPI upload endpoint. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the PyPI upload base URL (for testing).
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

// Verify checks if the detected PyPI API token is valid/active.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/legacy/", nil)
	if err != nil {
		slog.ErrorContext(ctx, "pypi verifier: failed to create request", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to create request: %v", err),
		}
	}
	req.SetBasicAuth("__token__", token)
	req.Header.Set("User-Agent", "leakwatch-verifier")

	client := v.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.ErrorContext(ctx, "pypi verifier: request failed", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("request failed: %v", err),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusMethodNotAllowed:
		slog.InfoContext(ctx, "pypi verifier: token is active")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedActive,
			Message: "PyPI API token is active",
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		slog.DebugContext(ctx, "pypi verifier: token is inactive")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "PyPI API token is invalid or revoked",
		}
	default:
		slog.ErrorContext(ctx, "pypi verifier: unexpected status code",
			slog.Int("status_code", resp.StatusCode),
		)
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
		}
	}
}
