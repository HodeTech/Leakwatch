// Package gcp provides a verifier for GCP service account keys.
//
// It validates the JSON structure without making any API calls. Because no
// live verification is performed, the result is always StatusUnverified: a
// valid structure does not prove the key is active, and an invalid structure
// does not prove it is inactive.
package gcp

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "gcp-service-account"

// Verifier checks whether a GCP service account key has a valid JSON structure.
// It NEVER logs or persists raw key values.
type Verifier struct{}

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// serviceAccountKey represents the expected structure of a GCP service account key file.
type serviceAccountKey struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	ClientEmail  string `json:"client_email"`
}

// Verify checks if the detected GCP service account key has a valid JSON structure.
//
// The detector puts the redacted service-account JSON block (the private_key PEM
// body replaced with "[REDACTED]", structure intact) in RawV2 and only the
// private_key_id in Raw. Validation therefore uses RawV2 when present, falling
// back to Raw for older/alternate detector output. The "[REDACTED]" placeholder
// does not affect the type/project_id/private_key_id/client_email checks.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	data := raw.RawV2
	if len(data) == 0 {
		data = raw.Raw
	}
	if len(data) == 0 {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty input",
		}
	}

	var key serviceAccountKey
	if err := json.Unmarshal(data, &key); err != nil {
		slog.DebugContext(
			ctx, "gcp verifier: failed to parse JSON",
			slog.String("error", err.Error()),
		)
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (invalid JSON structure); live verification not supported",
		}
	}

	if key.Type != "service_account" {
		slog.DebugContext(
			ctx, "gcp verifier: unexpected type field",
			slog.String("type", key.Type),
		)
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (JSON type field is not service_account); live verification not supported",
		}
	}

	if key.ProjectID == "" || key.PrivateKeyID == "" || key.ClientEmail == "" {
		slog.DebugContext(ctx, "gcp verifier: missing required fields")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (missing required fields in service account key); live verification not supported",
		}
	}

	slog.DebugContext(
		ctx, "gcp verifier: service account key format validated",
		slog.String("project_id", key.ProjectID),
		slog.String("client_email", key.ClientEmail),
	)

	return finding.VerificationResult{
		Status:  finding.StatusUnverified,
		Message: "format valid; live verification not supported (would require GCP OAuth2 token exchange)",
		ExtraData: map[string]string{
			"project_id":   key.ProjectID,
			"client_email": key.ClientEmail,
		},
	}
}
