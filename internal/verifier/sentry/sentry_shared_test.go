package sentry

import (
	"net/http"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/internal/verifier/internal/vtest"
)

func TestVerify_SharedSafetySuite(t *testing.T) {
	vtest.Run(t, vtest.Case{
		Name: "sentry",
		New: func(apiURL string, client *http.Client) verifier.Verifier {
			return &Verifier{apiURL: apiURL, httpClient: client}
		},
		Raw: detector.RawFinding{
			DetectorID: detectorID,
			Raw:        []byte("sntrys_eyJpYXQiOjE2OTkwMDAwMDB9_abcdef1234567890"),
			Redacted:   "sntrys_****7890",
		},
		// The Sentry verifier checks only the status code on success and does
		// not decode a body, so the malformed-body case does not apply.
		SkipMalformed: true,
	})
}
