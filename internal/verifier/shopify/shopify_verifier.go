// Package shopify provides a verifier for Shopify access tokens.
// It uses the Shopify Admin API GET /admin/api/2024-01/shop.json endpoint
// to check token validity. A store domain is required via ExtraData.
package shopify

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

const detectorID = "shopify-access-token"

// shopAPIPath is the Shopify Admin API endpoint for shop details.
const shopAPIPath = "/admin/api/2024-01/shop.json"

// Verifier checks whether a Shopify access token is active by calling the
// Shopify Admin API. It NEVER logs or persists raw token values.
type Verifier struct {
	// apiURL overrides the full base URL (for testing). When set, store_domain
	// from ExtraData is ignored and apiURL is used directly.
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

// Verify checks if the detected Shopify access token is valid/active.
// Raw contains the token value. ExtraData["store_domain"] must contain the
// Shopify store domain (e.g., "mystore.myshopify.com").
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	token := string(raw.Raw)
	if token == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty token",
		}
	}

	baseURL := v.apiURL
	if baseURL == "" {
		domain := raw.ExtraData["store_domain"]
		if domain == "" {
			return finding.VerificationResult{
				Status:  finding.StatusUnverified,
				Message: "store domain required for verification",
			}
		}
		baseURL = "https://" + domain
	}

	return httpx.VerifyToken(ctx, v.httpClient, token, httpx.TokenSpec{
		Name: "shopify",
		Request: httpx.Request{
			URL:    baseURL + shopAPIPath,
			Header: map[string]string{"X-Shopify-Access-Token": token},
		},
		ActiveMessage:   "Shopify access token is active",
		InactiveMessage: "Shopify access token is invalid or revoked",
		Decode:          decodeShop,
	})
}

// decodeShop reports the shop name as shop_name when present.
func decodeShop(body io.Reader) (map[string]string, string, error) {
	var shopResp struct {
		Shop struct {
			Name string `json:"name"`
		} `json:"shop"`
	}
	if err := json.NewDecoder(body).Decode(&shopResp); err != nil {
		return nil, "", err
	}
	extra := map[string]string{}
	if shopResp.Shop.Name != "" {
		extra["shop_name"] = shopResp.Shop.Name
	}
	return extra, "", nil
}
