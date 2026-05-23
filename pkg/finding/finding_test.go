package finding

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		severity Severity
		expected string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.severity.String())
		})
	}
}

func TestVerificationStatus_String(t *testing.T) {
	tests := []struct {
		status   VerificationStatus
		expected string
	}{
		{StatusUnverified, "unverified"},
		{StatusVerifiedActive, "verified_active"},
		{StatusVerifiedInactive, "verified_inactive"},
		{StatusVerifyError, "verify_error"},
		{VerificationStatus(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.String())
		})
	}
}

func TestSeverity_MarshalJSON_StringRepresentation(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
		expected string
	}{
		{"low", SeverityLow, `"low"`},
		{"medium", SeverityMedium, `"medium"`},
		{"high", SeverityHigh, `"high"`},
		{"critical", SeverityCritical, `"critical"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.severity)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestSeverity_MarshalJSON_InvalidValue_ReturnsError(t *testing.T) {
	_, err := json.Marshal(Severity(99))
	assert.Error(t, err)
}

func TestSeverity_UnmarshalJSON_RoundTrip_PreservesValue(t *testing.T) {
	tests := []struct {
		name     string
		severity Severity
	}{
		{"low", SeverityLow},
		{"medium", SeverityMedium},
		{"high", SeverityHigh},
		{"critical", SeverityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.severity)
			require.NoError(t, err)

			var decoded Severity
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)
			assert.Equal(t, tt.severity, decoded)
		})
	}
}

func TestSeverity_UnmarshalJSON_InvalidString_ReturnsError(t *testing.T) {
	var s Severity
	err := json.Unmarshal([]byte(`"bogus"`), &s)
	assert.Error(t, err)
}

func TestSeverity_UnmarshalJSON_InvalidType_ReturnsError(t *testing.T) {
	var s Severity
	err := json.Unmarshal([]byte(`3`), &s)
	assert.Error(t, err)
}

func TestVerificationStatus_MarshalJSON_StringRepresentation(t *testing.T) {
	tests := []struct {
		name     string
		status   VerificationStatus
		expected string
	}{
		{"unverified", StatusUnverified, `"unverified"`},
		{"verified_active", StatusVerifiedActive, `"verified_active"`},
		{"verified_inactive", StatusVerifiedInactive, `"verified_inactive"`},
		{"verify_error", StatusVerifyError, `"verify_error"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.status)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestVerificationStatus_MarshalJSON_InvalidValue_ReturnsError(t *testing.T) {
	_, err := json.Marshal(VerificationStatus(99))
	assert.Error(t, err)
}

func TestVerificationStatus_UnmarshalJSON_RoundTrip_PreservesValue(t *testing.T) {
	tests := []struct {
		name   string
		status VerificationStatus
	}{
		{"unverified", StatusUnverified},
		{"verified_active", StatusVerifiedActive},
		{"verified_inactive", StatusVerifiedInactive},
		{"verify_error", StatusVerifyError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.status)
			require.NoError(t, err)

			var decoded VerificationStatus
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)
			assert.Equal(t, tt.status, decoded)
		})
	}
}

func TestVerificationStatus_UnmarshalJSON_InvalidString_ReturnsError(t *testing.T) {
	var v VerificationStatus
	err := json.Unmarshal([]byte(`"bogus"`), &v)
	assert.Error(t, err)
}

func TestVerificationStatus_UnmarshalJSON_InvalidType_ReturnsError(t *testing.T) {
	var v VerificationStatus
	err := json.Unmarshal([]byte(`0`), &v)
	assert.Error(t, err)
}

func TestFinding_JSONMarshalUnmarshal_SeverityAsString(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	f := Finding{
		ID:         "test-123",
		DetectorID: "aws-access-key-id",
		Severity:   SeverityCritical,
		Redacted:   "AKIA****MPLE",
		SourceMetadata: SourceMetadata{
			SourceType: "filesystem",
			FilePath:   "config.yaml",
			Line:       42,
		},
		Verification: VerificationResult{
			Status: StatusUnverified,
		},
		DetectedAt: now,
		Entropy:    4.5,
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	// Severity should serialize as "critical" string, not integer 3
	var rawJSON map[string]interface{}
	err = json.Unmarshal(data, &rawJSON)
	require.NoError(t, err)
	assert.Equal(t, "critical", rawJSON["severity"], "Severity should serialize as string in JSON")

	// Verification status should also appear as string
	verification, ok := rawJSON["verification"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "unverified", verification["status"], "VerificationStatus should serialize as string in JSON")

	var decoded Finding
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, f.ID, decoded.ID)
	assert.Equal(t, f.DetectorID, decoded.DetectorID)
	assert.Equal(t, f.Severity, decoded.Severity)
	assert.Equal(t, f.Redacted, decoded.Redacted)
	assert.Equal(t, f.SourceMetadata.FilePath, decoded.SourceMetadata.FilePath)
	assert.Equal(t, f.SourceMetadata.Line, decoded.SourceMetadata.Line)
	assert.Equal(t, f.Verification.Status, decoded.Verification.Status)
	assert.Empty(t, decoded.Raw) // Raw is never serialized via json:"-"
}

func TestFinding_JSONOmitsEmptyRaw(t *testing.T) {
	f := Finding{
		ID:       "test-1",
		Redacted: "AKIA****MPLE",
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	_, hasRaw := m["raw"]
	assert.False(t, hasRaw, "raw field should not appear in JSON when empty")
}

// TestFinding_JSONNeverSerializesRaw verifies the type-level redaction: even
// when Raw holds a (fake) secret, the standard json.Marshal MUST NOT emit it.
// This is the defense that protects external consumers which marshal Findings
// directly without going through Leakwatch's output formatters.
func TestFinding_JSONNeverSerializesRaw(t *testing.T) {
	f := Finding{
		ID:       "test-1",
		Redacted: "AKIA****MPLE",
		Raw:      "AKIAIOSFODNN7EXAMPLE", // fake, well-known AWS docs example value
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "AKIAIOSFODNN7EXAMPLE",
		"Raw must never appear in standard JSON output")

	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	_, hasRaw := m["raw"]
	assert.False(t, hasRaw, "raw field must never appear in JSON regardless of value")
}
