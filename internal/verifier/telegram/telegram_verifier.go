// Package telegram provides a verifier for Telegram Bot tokens.
// It uses the Telegram Bot API GET /bot{token}/getMe endpoint to check token validity.
package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/bot"+token+"/getMe", nil)
	if err != nil {
		// The error text may embed the request URL, which contains the token;
		// redact it before logging or returning.
		safeErr := httpx.RedactError(err, token)
		slog.ErrorContext(ctx, "telegram verifier: failed to create request", slog.String("error", safeErr))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to create request: %s", safeErr),
		}
	}
	req.Header.Set("User-Agent", "leakwatch-verifier")

	client := v.httpClient
	if client == nil {
		client = httpx.Client()
	}

	resp, err := client.Do(req)
	if err != nil {
		// A *url.Error from the transport embeds the full request URL (and thus
		// the token); redact it before logging or returning.
		safeErr := httpx.RedactError(err, token)
		slog.ErrorContext(ctx, "telegram verifier: request failed", slog.String("error", safeErr))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("request failed: %s", safeErr),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	// A redirect from an API endpoint means the credential context is wrong
	// (for example a login redirect or a moved host). The shared client does
	// not follow redirects so the credential is never re-sent to the redirect
	// target; treat it as a verification error rather than an active secret.
	if httpx.IsRedirect(resp.StatusCode) {
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected redirect (status %d)", resp.StatusCode),
		}
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return handleOKResponse(ctx, resp.Body)
	case http.StatusUnauthorized:
		slog.DebugContext(ctx, "telegram verifier: token is inactive")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "Telegram Bot token is invalid or revoked",
		}
	default:
		slog.ErrorContext(
			ctx, "telegram verifier: unexpected status code",
			slog.Int("status_code", resp.StatusCode),
		)
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
		}
	}
}

// handleOKResponse parses the Telegram Bot API response for a 200 status.
func handleOKResponse(ctx context.Context, body io.Reader) finding.VerificationResult {
	var response struct {
		OK     bool `json:"ok"`
		Result struct {
			Username string `json:"username"`
		} `json:"result"`
	}

	if err := json.NewDecoder(httpx.LimitReader(body)).Decode(&response); err != nil {
		slog.ErrorContext(ctx, "telegram verifier: failed to decode response", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("200 OK but failed to decode response body: %v", err),
		}
	}

	if !response.OK {
		slog.DebugContext(ctx, "telegram verifier: response ok=false")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "Telegram Bot token returned ok=false",
		}
	}

	extra := map[string]string{
		"username": response.Result.Username,
	}

	slog.InfoContext(
		ctx, "telegram verifier: token is active",
		slog.String("username", response.Result.Username),
	)

	return finding.VerificationResult{
		Status:    finding.StatusVerifiedActive,
		Message:   "Telegram Bot token is active",
		ExtraData: extra,
	}
}
