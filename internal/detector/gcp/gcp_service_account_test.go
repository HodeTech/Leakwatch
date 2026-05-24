package gcp

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "gcp-service-account", d.ID())
	assert.Equal(t, "GCP Service Account Key", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidServiceAccount(t *testing.T) {
	fullJSON := `{
  "type": "service_account",
  "project_id": "my-project-123",
  "private_key_id": "abcdef1234567890abcdef1234567890abcdef12",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nREDACTED\n-----END RSA PRIVATE KEY-----\n",
  "client_email": "my-service@my-project-123.iam.gserviceaccount.com",
  "client_id": "123456789012345678901"
}`

	minimalJSON := `{
  "type": "service_account",
  "project_id": "test-project"
}`

	spacedJSON := `{
  "type"  :  "service_account",
  "private_key_id": "def0123456789abcdef0123456789abcdef01234",
  "client_email": "svc@proj.iam.gserviceaccount.com"
}`

	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
		keyID    string
		email    string
	}{
		{
			name:     "full service account JSON",
			input:    fullJSON,
			expected: 1,
			redacted: "****@*.iam.gserviceaccount.com",
			keyID:    "abcdef1234567890abcdef1234567890abcdef12",
			email:    "my-service@my-project-123.iam.gserviceaccount.com",
		},
		{
			name:     "minimal JSON without private key id",
			input:    minimalJSON,
			expected: 1,
			redacted: "GCP Service Account Key ****",
		},
		{
			name:     "JSON with extra spaces around colon",
			input:    spacedJSON,
			expected: 1,
			redacted: "****@*.iam.gserviceaccount.com",
			keyID:    "def0123456789abcdef0123456789abcdef01234",
			email:    "svc@proj.iam.gserviceaccount.com",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
				if tt.keyID != "" {
					assert.Equal(t, tt.keyID, string(findings[0].Raw))
					assert.Equal(t, tt.keyID, findings[0].ExtraData["private_key_id"])
				}
				if tt.email != "" {
					assert.Equal(t, tt.email, findings[0].ExtraData["client_email"])
				}
			}
		})
	}
}

// fakePEM is a clearly fake, redacted private key body. It contains no real key
// material and is only used to assert that the PEM is never leaked into findings.
const fakePEM = `-----BEGIN PRIVATE KEY-----\nFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n-----END PRIVATE KEY-----\n`

func TestDetector_Scan_TwoAccounts_ReturnsDistinctFindingsWithoutKeyLeak(t *testing.T) {
	// A JSON array holding two distinct service accounts, each with its own
	// (fake) private_key, private_key_id, and client_email.
	twoAccounts := `[
  {
    "type": "service_account",
    "project_id": "project-one",
    "private_key_id": "1111111111111111111111111111111111111111",
    "private_key": "` + fakePEM + `",
    "client_email": "svc-one@project-one.iam.gserviceaccount.com"
  },
  {
    "type": "service_account",
    "project_id": "project-two",
    "private_key_id": "2222222222222222222222222222222222222222",
    "private_key": "` + fakePEM + `",
    "client_email": "svc-two@project-two.iam.gserviceaccount.com"
  }
]`

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(twoAccounts))

	require.Len(t, findings, 2)

	// Each finding must carry its OWN private_key_id and client_email, not the
	// first account's fields repeated.
	keyIDs := []string{
		findings[0].ExtraData["private_key_id"],
		findings[1].ExtraData["private_key_id"],
	}
	emails := []string{
		findings[0].ExtraData["client_email"],
		findings[1].ExtraData["client_email"],
	}
	assert.ElementsMatch(t, []string{
		"1111111111111111111111111111111111111111",
		"2222222222222222222222222222222222222222",
	}, keyIDs)
	assert.ElementsMatch(t, []string{
		"svc-one@project-one.iam.gserviceaccount.com",
		"svc-two@project-two.iam.gserviceaccount.com",
	}, emails)
	assert.NotEqual(t, keyIDs[0], keyIDs[1], "findings must have distinct key IDs")

	// No finding may leak the private_key PEM body in Raw, RawV2, or Redacted,
	// and RawV2 must be scoped to a single account (never the whole file).
	for i, f := range findings {
		assert.NotContains(t, string(f.Raw), "PRIVATE KEY", "finding %d Raw", i)
		assert.NotContains(t, string(f.RawV2), "FAKEFAKE", "finding %d RawV2 PEM body", i)
		assert.NotContains(t, f.Redacted, "PRIVATE KEY", "finding %d Redacted", i)
		// RawV2 should contain exactly one service_account marker.
		assert.Equal(t, 1, strings.Count(string(f.RawV2), "service_account"),
			"finding %d RawV2 should be scoped to one account", i)
	}

	// The two RawV2 blocks must differ (distinct account data).
	assert.NotEqual(t, string(findings[0].RawV2), string(findings[1].RawV2))
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "type user_account instead of service_account",
			input: `{"type": "user_account", "client_email": "user@example.com"}`,
		},
		{
			name:  "plain text with service_account word",
			input: "Please create a service_account for this project",
		},
		{
			name:  "empty JSON object",
			input: "{}",
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}
