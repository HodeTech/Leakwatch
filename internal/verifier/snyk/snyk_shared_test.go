package snyk

import (
	"net/http"
	"testing"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "snyk",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &Verifier{apiURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte("test-snyk-api-key-abcdef1234567890"),
			Redacted:   "****7890",
		},
		// The Snyk verifier checks only the status code on success and does not
		// decode a body, so the malformed-body case does not apply.
		SkipMalformed: true,
	})
}
