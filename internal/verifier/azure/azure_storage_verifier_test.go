package azure

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

func TestStorageVerify_ValidConnectionString_ReturnsUnverified(t *testing.T) {
	v := &StorageVerifier{}

	raw := detector.RawFinding{
		DetectorID: storageDetectorID,
		Raw:        []byte("DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=SGVsbG9Xb3JsZA==;EndpointSuffix=core.windows.net"),
		Redacted:   "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=****",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
	assert.Equal(t, "mystorageaccount", result.ExtraData["account_name"])
}

func TestStorageVerify_MissingAccountName_ReturnsUnverified(t *testing.T) {
	v := &StorageVerifier{}

	raw := detector.RawFinding{
		DetectorID: storageDetectorID,
		Raw:        []byte("DefaultEndpointsProtocol=https;AccountKey=SGVsbG9Xb3JsZA==;EndpointSuffix=core.windows.net"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestStorageVerify_MissingAccountKey_ReturnsUnverified(t *testing.T) {
	v := &StorageVerifier{}

	raw := detector.RawFinding{
		DetectorID: storageDetectorID,
		Raw:        []byte("DefaultEndpointsProtocol=https;AccountName=mystorageaccount;EndpointSuffix=core.windows.net"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestStorageVerify_InvalidBase64Key_ReturnsUnverified(t *testing.T) {
	v := &StorageVerifier{}

	raw := detector.RawFinding{
		DetectorID: storageDetectorID,
		Raw:        []byte("DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=not-valid-base64!!!"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestStorageVerify_EmptyConnectionString_ReturnsUnverified(t *testing.T) {
	v := &StorageVerifier{}

	raw := detector.RawFinding{
		DetectorID: storageDetectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty connection string", result.Message)
}

func TestStorageVerify_Type_ReturnsCorrectID(t *testing.T) {
	v := &StorageVerifier{}
	assert.Equal(t, "azure-storage-key", v.Type())
}

func TestStorageVerify_KeyWithBase64Padding_ReturnsUnverified(t *testing.T) {
	v := &StorageVerifier{}

	// A proper base64 key with padding characters.
	raw := detector.RawFinding{
		DetectorID: storageDetectorID,
		Raw:        []byte("AccountName=teststorage;AccountKey=dGVzdGtleXZhbHVl"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	require.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "teststorage", result.ExtraData["account_name"])
}
