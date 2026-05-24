package gcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	detectorgcp "github.com/HodeTech/leakwatch/internal/detector/gcp"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestVerifier_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "gcp-service-account", v.Type())
}

// TestVerify_RawV2RedactedBlock_ReturnsFormatValid feeds the verifier a finding
// shaped like the real detector output: RawV2 holds the service-account JSON
// block with the private_key body replaced by "[REDACTED]" (structure intact),
// while Raw carries only the private_key_id. The verifier must validate RawV2.
func TestVerify_RawV2RedactedBlock_ReturnsFormatValid(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("key-id-abc"),
		RawV2: []byte(`{
			"type": "service_account",
			"project_id": "my-project-123",
			"private_key_id": "key-id-abc",
			"private_key": "[REDACTED]",
			"client_email": "sa@my-project-123.iam.gserviceaccount.com",
			"client_id": "123456789"
		}`),
		Redacted: "****@*.iam.gserviceaccount.com",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
	assert.Equal(t, "my-project-123", result.ExtraData["project_id"])
	assert.Equal(t, "sa@my-project-123.iam.gserviceaccount.com", result.ExtraData["client_email"])
}

// TestVerify_OnlyRawFullJSON_ReturnsFormatValid covers the fallback path where
// RawV2 is empty and Raw still carries the full JSON (older/alternate output).
func TestVerify_OnlyRawFullJSON_ReturnsFormatValid(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw: []byte(`{
			"type": "service_account",
			"project_id": "my-project-123",
			"private_key_id": "key-id-abc",
			"private_key": "-----BEGIN RSA PRIVATE KEY-----\nREDACTED\n-----END RSA PRIVATE KEY-----\n",
			"client_email": "sa@my-project-123.iam.gserviceaccount.com",
			"client_id": "123456789"
		}`),
		Redacted: "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
	assert.Equal(t, "my-project-123", result.ExtraData["project_id"])
	assert.Equal(t, "sa@my-project-123.iam.gserviceaccount.com", result.ExtraData["client_email"])
}

// TestVerify_DetectorOutputContract runs the real detector and feeds its output
// straight into the verifier, locking the Raw/RawV2 contract between the two.
func TestVerify_DetectorOutputContract(t *testing.T) {
	d := &detectorgcp.Detector{}

	// A representative service-account JSON. The private_key value is a fake
	// placeholder, never a real key.
	input := []byte(`{
		"type": "service_account",
		"project_id": "contract-project",
		"private_key_id": "contract-key-id",
		"private_key": "-----BEGIN PRIVATE KEY-----\nFAKEFAKEFAKE\n-----END PRIVATE KEY-----\n",
		"client_email": "contract@contract-project.iam.gserviceaccount.com",
		"client_id": "987654321"
	}`)

	findings := d.Scan(context.Background(), input)
	require.Len(t, findings, 1)

	// Lock the detector contract the verifier depends on.
	require.NotEmpty(t, findings[0].RawV2, "detector must populate RawV2")
	assert.NotContains(t, string(findings[0].RawV2), "FAKEFAKEFAKE",
		"private_key body must be redacted in RawV2")

	v := &Verifier{}
	result := v.Verify(context.Background(), findings[0])

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
	assert.Equal(t, "contract-project", result.ExtraData["project_id"])
	assert.Equal(t, "contract@contract-project.iam.gserviceaccount.com", result.ExtraData["client_email"])
}

func TestVerify_InvalidJSON_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		RawV2:      []byte(`{not valid json`),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_WrongType_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		RawV2: []byte(`{
			"type": "authorized_user",
			"project_id": "my-project",
			"private_key_id": "key-id",
			"client_email": "user@example.com"
		}`),
		Redacted: "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_MissingFields_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		RawV2: []byte(`{
			"type": "service_account",
			"project_id": "my-project"
		}`),
		Redacted: "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_EmptyInput_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(""),
		RawV2:      []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty input", result.Message)
}
