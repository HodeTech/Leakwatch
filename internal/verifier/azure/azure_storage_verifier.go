// Package azure provides verifiers for Azure secrets.
// The storage verifier performs format validation on Azure Storage connection strings.
package azure

import (
	"context"
	"encoding/base64"
	"log/slog"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const storageDetectorID = "azure-storage-key"

// StorageVerifier validates Azure Storage connection strings by checking
// that the required fields (AccountName, AccountKey) are present and
// the AccountKey is valid base64. It NEVER logs or persists raw key values.
//
// Note: This is a format-check verifier; it performs no live verification.
// The result is therefore always StatusUnverified. Live verification would
// require the Azure SDK to perform HMAC-SHA256 signed requests.
type StorageVerifier struct{}

func init() {
	verifier.Register(&StorageVerifier{})
}

// Type returns the detector ID this verifier handles.
func (v *StorageVerifier) Type() string {
	return storageDetectorID
}

// Verify checks if the detected Azure Storage connection string has valid format.
// Raw contains the full connection string.
func (v *StorageVerifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	connStr := string(raw.Raw)
	if connStr == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty connection string",
		}
	}

	accountName, accountKey := parseConnectionString(connStr)

	if accountName == "" {
		slog.DebugContext(ctx, "azure storage verifier: AccountName not found in connection string")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (AccountName not found in connection string); live verification not supported",
		}
	}

	if accountKey == "" {
		slog.DebugContext(ctx, "azure storage verifier: AccountKey not found in connection string")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (AccountKey not found in connection string); live verification not supported",
		}
	}

	// Validate that AccountKey is valid base64.
	if _, err := base64.StdEncoding.DecodeString(accountKey); err != nil {
		slog.DebugContext(
			ctx, "azure storage verifier: AccountKey is not valid base64",
			slog.String("error", err.Error()),
		)
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (AccountKey is not valid base64); live verification not supported",
		}
	}

	extra := map[string]string{
		"account_name": accountName,
	}

	slog.DebugContext(
		ctx, "azure storage verifier: connection string format is valid",
		slog.String("account_name", accountName),
	)

	return finding.VerificationResult{
		Status:    finding.StatusUnverified,
		Message:   "format valid; live verification not supported (requires Azure SDK)",
		ExtraData: extra,
	}
}

// parseConnectionString extracts AccountName and AccountKey from an Azure
// Storage connection string of the form "Key1=Value1;Key2=Value2;...".
func parseConnectionString(connStr string) (accountName, accountKey string) {
	for _, part := range strings.Split(connStr, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "accountname":
			accountName = strings.TrimSpace(v)
		case "accountkey":
			// AccountKey values may contain '=' (base64 padding), so rejoin
			// any remaining parts. Since we split on ';' first and then Cut
			// on first '=', the value already includes everything after the
			// first '='.
			accountKey = strings.TrimSpace(v)
		}
	}
	return accountName, accountKey
}
