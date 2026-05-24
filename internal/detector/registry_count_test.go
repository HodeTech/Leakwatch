package detector_test

// This golden test pins the number of compile-time registered detectors so that
// accidentally dropping a detector (or a duplicate ID silently shadowing one)
// is caught immediately. It lives in the external detector_test package so it
// can blank-import every detector subpackage without creating an import cycle
// (each subpackage imports the detector package under test).
//
// Counts measured from the codebase:
//   - 63 detectors registered at compile time via init() (detector.Register).
//   - 59 packages register statically; azure, github, slack and stripe each
//     register two detectors (59 + 4 = 63).
//   - 60 detector subpackages exist in total; the 60th, "custom", registers its
//     rules at runtime (detector.RegisterIfAbsent) and is therefore not part of
//     the compile-time count.
//
// If you add or remove a detector, update wantDetectorCount below and keep the
// blank-import block in sync with cmd/imports.go.

import (
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/stretchr/testify/assert"

	// Each blank import runs the package's init(), registering its detector(s)
	// so the golden count below sees the full compile-time set. The per-line
	// comments mirror cmd/imports.go and satisfy the no-blank-import-without-
	// comment lint rule.
	_ "github.com/HodeTech/leakwatch/internal/detector/airtable"     // register airtable detector
	_ "github.com/HodeTech/leakwatch/internal/detector/anthropic"    // register anthropic detector
	_ "github.com/HodeTech/leakwatch/internal/detector/auth0"        // register auth0 detector
	_ "github.com/HodeTech/leakwatch/internal/detector/aws"          // register aws detector
	_ "github.com/HodeTech/leakwatch/internal/detector/azure"        // register azure detectors (storage + entra)
	_ "github.com/HodeTech/leakwatch/internal/detector/bitbucket"    // register bitbucket detector
	_ "github.com/HodeTech/leakwatch/internal/detector/circleci"     // register circleci detector
	_ "github.com/HodeTech/leakwatch/internal/detector/cloudflare"   // register cloudflare detector
	_ "github.com/HodeTech/leakwatch/internal/detector/coinbase"     // register coinbase detector
	_ "github.com/HodeTech/leakwatch/internal/detector/databricks"   // register databricks detector
	_ "github.com/HodeTech/leakwatch/internal/detector/datadog"      // register datadog detector
	_ "github.com/HodeTech/leakwatch/internal/detector/dbconn"       // register database connection-string detector
	_ "github.com/HodeTech/leakwatch/internal/detector/deepseek"     // register deepseek detector
	_ "github.com/HodeTech/leakwatch/internal/detector/digitalocean" // register digitalocean detector
	_ "github.com/HodeTech/leakwatch/internal/detector/discord"      // register discord detector
	_ "github.com/HodeTech/leakwatch/internal/detector/dockerhub"    // register dockerhub detector
	_ "github.com/HodeTech/leakwatch/internal/detector/doppler"      // register doppler detector
	_ "github.com/HodeTech/leakwatch/internal/detector/figma"        // register figma detector
	_ "github.com/HodeTech/leakwatch/internal/detector/ftp"          // register ftp credentials detector
	_ "github.com/HodeTech/leakwatch/internal/detector/gcp"          // register gcp service-account detector
	_ "github.com/HodeTech/leakwatch/internal/detector/generic"      // register generic api-key detector
	_ "github.com/HodeTech/leakwatch/internal/detector/github"       // register github detectors (pat + oauth)
	_ "github.com/HodeTech/leakwatch/internal/detector/gitlab"       // register gitlab detector
	_ "github.com/HodeTech/leakwatch/internal/detector/grafana"      // register grafana detector
	_ "github.com/HodeTech/leakwatch/internal/detector/heroku"       // register heroku detector
	_ "github.com/HodeTech/leakwatch/internal/detector/huggingface"  // register huggingface detector
	_ "github.com/HodeTech/leakwatch/internal/detector/infura"       // register infura detector
	_ "github.com/HodeTech/leakwatch/internal/detector/jwt"          // register jwt detector
	_ "github.com/HodeTech/leakwatch/internal/detector/launchdarkly" // register launchdarkly detector
	_ "github.com/HodeTech/leakwatch/internal/detector/ldap"         // register ldap credentials detector
	_ "github.com/HodeTech/leakwatch/internal/detector/linear"       // register linear detector
	_ "github.com/HodeTech/leakwatch/internal/detector/mailgun"      // register mailgun detector
	_ "github.com/HodeTech/leakwatch/internal/detector/newrelic"     // register newrelic detector
	_ "github.com/HodeTech/leakwatch/internal/detector/notion"       // register notion detector
	_ "github.com/HodeTech/leakwatch/internal/detector/npm"          // register npm detector
	_ "github.com/HodeTech/leakwatch/internal/detector/okta"         // register okta detector
	_ "github.com/HodeTech/leakwatch/internal/detector/openai"       // register openai detector
	_ "github.com/HodeTech/leakwatch/internal/detector/pagerduty"    // register pagerduty detector
	_ "github.com/HodeTech/leakwatch/internal/detector/postmark"     // register postmark detector
	_ "github.com/HodeTech/leakwatch/internal/detector/privatekey"   // register private-key detector (RSA, SSH, DSA, EC, PGP)
	_ "github.com/HodeTech/leakwatch/internal/detector/pypi"         // register pypi detector
	_ "github.com/HodeTech/leakwatch/internal/detector/rabbitmq"     // register rabbitmq detector
	_ "github.com/HodeTech/leakwatch/internal/detector/redis"        // register redis detector
	_ "github.com/HodeTech/leakwatch/internal/detector/rubygems"     // register rubygems detector
	_ "github.com/HodeTech/leakwatch/internal/detector/sendgrid"     // register sendgrid detector
	_ "github.com/HodeTech/leakwatch/internal/detector/sentry"       // register sentry detector
	_ "github.com/HodeTech/leakwatch/internal/detector/shopify"      // register shopify detector
	_ "github.com/HodeTech/leakwatch/internal/detector/slack"        // register slack detectors (token + webhook)
	_ "github.com/HodeTech/leakwatch/internal/detector/snowflake"    // register snowflake detector
	_ "github.com/HodeTech/leakwatch/internal/detector/snyk"         // register snyk detector
	_ "github.com/HodeTech/leakwatch/internal/detector/sonarcloud"   // register sonarcloud detector
	_ "github.com/HodeTech/leakwatch/internal/detector/stripe"       // register stripe detectors (live + test)
	_ "github.com/HodeTech/leakwatch/internal/detector/supabase"     // register supabase detector
	_ "github.com/HodeTech/leakwatch/internal/detector/teams"        // register microsoft teams webhook detector
	_ "github.com/HodeTech/leakwatch/internal/detector/telegram"     // register telegram detector
	_ "github.com/HodeTech/leakwatch/internal/detector/terraform"    // register terraform cloud detector
	_ "github.com/HodeTech/leakwatch/internal/detector/twilio"       // register twilio detector
	_ "github.com/HodeTech/leakwatch/internal/detector/vault"        // register hashicorp vault detector
	_ "github.com/HodeTech/leakwatch/internal/detector/vercel"       // register vercel detector
)

// wantDetectorCount is the expected number of compile-time registered detectors.
const wantDetectorCount = 63

// registeredAtInit snapshots the registry right after every blank-imported
// detector package has run its init(), but before any test can mutate the
// global registry (the in-package registry_test.go calls detector.Reset()).
// Capturing here makes the golden assertion independent of test ordering.
var registeredAtInit []detector.Detector

func init() {
	registeredAtInit = detector.All()
}

func TestAll_RegisteredDetectorCount_MatchesGolden(t *testing.T) {
	assert.Len(t, registeredAtInit, wantDetectorCount,
		"compile-time registered detector count drifted; update wantDetectorCount and cmd/imports.go together")

	// Every registered detector must have a unique, non-empty ID.
	ids := make(map[string]bool, len(registeredAtInit))
	for _, d := range registeredAtInit {
		assert.NotEmpty(t, d.ID())
		assert.False(t, ids[d.ID()], "duplicate detector ID: %s", d.ID())
		ids[d.ID()] = true
	}
}
