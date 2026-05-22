// Package infura provides a verifier for Infura API keys.
// It uses the Infura JSON-RPC endpoint POST /v3/{token} to check key validity.
package infura

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
	"github.com/cemililik/leakwatch/internal/verifier/internal/httpx"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const detectorID = "infura-api-key"

// defaultAPIURL is the base URL for the Infura JSON-RPC API.
const defaultAPIURL = "https://mainnet.infura.io/v3"

// Verifier checks whether an Infura API key is active by calling the
// Infura JSON-RPC endpoint. It NEVER logs or persists raw key values.
type Verifier struct {
	// apiURL overrides the Infura API base URL (for testing).
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

// Verify checks if the detected Infura API key is valid/active.
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

	requestBody := []byte(`{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+"/"+token, bytes.NewReader(requestBody))
	if err != nil {
		// The error text may embed the request URL, which contains the token;
		// redact it before logging or returning.
		safeErr := httpx.RedactError(err, token)
		slog.ErrorContext(ctx, "infura verifier: failed to create request", slog.String("error", safeErr))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("failed to create request: %s", safeErr),
		}
	}
	req.Header.Set("Content-Type", "application/json")
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
		slog.ErrorContext(ctx, "infura verifier: request failed", slog.String("error", safeErr))
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
		return handleActiveKey(ctx, resp.Body)
	case http.StatusUnauthorized, http.StatusForbidden:
		slog.DebugContext(ctx, "infura verifier: API key is inactive")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "Infura API key is invalid or revoked",
		}
	default:
		slog.ErrorContext(
			ctx, "infura verifier: unexpected status code",
			slog.Int("status_code", resp.StatusCode),
		)
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
		}
	}
}

// handleActiveKey parses the Infura JSON-RPC response for a valid key.
func handleActiveKey(ctx context.Context, body io.Reader) finding.VerificationResult {
	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(httpx.LimitReader(body)).Decode(&rpcResp); err != nil {
		slog.ErrorContext(ctx, "infura verifier: failed to decode response", slog.String("error", err.Error()))
		return finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: "failed to decode JSON-RPC response",
		}
	}

	if rpcResp.Error != nil {
		slog.DebugContext(
			ctx, "infura verifier: API key returned error response",
			slog.String("error_message", rpcResp.Error.Message),
		)
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "Infura API key is invalid or revoked",
		}
	}

	if rpcResp.Result == "" {
		slog.DebugContext(ctx, "infura verifier: API key returned empty result")
		return finding.VerificationResult{
			Status:  finding.StatusVerifiedInactive,
			Message: "Infura API key is invalid or revoked",
		}
	}

	slog.InfoContext(ctx, "infura verifier: API key is active")

	return finding.VerificationResult{
		Status:  finding.StatusVerifiedActive,
		Message: "Infura API key is active",
	}
}
