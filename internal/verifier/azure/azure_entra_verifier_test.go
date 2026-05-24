package azure

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestEntraVerify_ValidSecret_ReturnsUnverified(t *testing.T) {
	v := &EntraVerifier{}

	raw := detector.RawFinding{
		DetectorID: entraDetectorID,
		Raw:        []byte("abc123DEF456ghi789JKL012mno345PQR678s"),
		Redacted:   "abc1****78s",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
}

func TestEntraVerify_ValidSecretWithSpecialChars_ReturnsUnverified(t *testing.T) {
	v := &EntraVerifier{}

	// 38-character secret with hyphens, underscores, periods, tildes.
	raw := detector.RawFinding{
		DetectorID: entraDetectorID,
		Raw:        []byte("abc-DEF_GHI.JKL~MNO123456789012345678"),
		Redacted:   "abc-****5678",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusUnverified, result.Status)
}

func TestEntraVerify_TooShort_ReturnsUnverified(t *testing.T) {
	v := &EntraVerifier{}

	raw := detector.RawFinding{
		DetectorID: entraDetectorID,
		Raw:        []byte("abc123DEF456ghi789JKL012mno345PQR"),
		Redacted:   "abc1****PQR",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestEntraVerify_TooLong_ReturnsUnverified(t *testing.T) {
	v := &EntraVerifier{}

	raw := detector.RawFinding{
		DetectorID: entraDetectorID,
		Raw:        []byte("abc123DEF456ghi789JKL012mno345PQR678stuv0"),
		Redacted:   "abc1****tuv0",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestEntraVerify_InvalidChars_ReturnsUnverified(t *testing.T) {
	v := &EntraVerifier{}

	raw := detector.RawFinding{
		DetectorID: entraDetectorID,
		Raw:        []byte("abc123DEF456ghi789JKL012mno345PQR!@#$"),
		Redacted:   "abc1****!@#$",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestEntraVerify_EmptySecret_ReturnsUnverified(t *testing.T) {
	v := &EntraVerifier{}

	raw := detector.RawFinding{
		DetectorID: entraDetectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty secret", result.Message)
}

func TestEntraVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &EntraVerifier{}
	assert.Equal(t, "azure-entra-secret", v.Type())
}

func TestEntraVerify_ExactLength34_ReturnsUnverified(t *testing.T) {
	v := &EntraVerifier{}

	raw := detector.RawFinding{
		DetectorID: entraDetectorID,
		Raw:        []byte("abcdefghijklmnopqrstuvwxyz12345678"),
		Redacted:   "abcd****5678",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
}

func TestEntraVerify_ExactLength40_ReturnsUnverified(t *testing.T) {
	v := &EntraVerifier{}

	raw := detector.RawFinding{
		DetectorID: entraDetectorID,
		Raw:        []byte("abcdefghijklmnopqrstuvwxyz12345678901234"),
		Redacted:   "abcd****1234",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
}
