// Package infura provides a verifier for Infura API keys.
// It uses the Infura JSON-RPC endpoint POST /v3/{token} to check key validity.
package infura

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

const detectorID = "infura-api-key"

// defaultAPIURL is the base URL for the Infura JSON-RPC API.
const defaultAPIURL = "https://mainnet.infura.io/v3"

// rpcProbe is the JSON-RPC body sent to exercise the key without side effects.
var rpcProbe = []byte(`{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}`)

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
// The key is embedded in the request URL, so it is set as Redact to keep it out
// of any transport error text.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	apiURL := httpx.BaseURL(v.apiURL, defaultAPIURL)

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "infura",
		Request: httpx.Request{
			Method: http.MethodPost,
			URL:    apiURL + "/" + token,
			Body:   rpcProbe,
			Header: map[string]string{"Content-Type": "application/json"},
		},
		Redact:           token,
		InactiveStatuses: []int{http.StatusUnauthorized, http.StatusForbidden},
		ActiveMessage:    "Infura API key is active",
		InactiveMessage:  "Infura API key is invalid or revoked",
		Decode:           decodeClientVersion,
	})
}

// decodeClientVersion downgrades a 200 response to inactive when the JSON-RPC
// body carries an error or an empty result.
func decodeClientVersion(body io.Reader) (map[string]string, string, error) {
	var rpcResp struct {
		Result string `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(body).Decode(&rpcResp); err != nil {
		return nil, "", err
	}
	if rpcResp.Error != nil || rpcResp.Result == "" {
		return nil, "Infura API key is invalid or revoked", nil
	}
	return nil, "", nil
}
