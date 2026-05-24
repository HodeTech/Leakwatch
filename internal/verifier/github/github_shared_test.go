package github

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "github",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &Verifier{apiURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"),
			Redacted:   "ghp_****ef12",
		},
	})
}

func TestOAuthVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "github-oauth",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &OAuthVerifier{apiURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: oauthDetectorID,
			Raw:        []byte("gho_somevalidtoken123456789012345678901"),
			Redacted:   "gho_****8901",
		},
	})
}
