package azure

import (
	"context"
	"log/slog"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const entraDetectorID = "azure-entra-secret"

// entraSecretPattern matches Azure Entra (formerly Azure AD) client secrets.
// Valid secrets are 34-40 characters containing alphanumerics, hyphens,
// underscores, periods, and tildes.
var entraSecretPattern = regexp.MustCompile(`^[A-Za-z0-9\-_~.]{34,40}$`)

// EntraVerifier validates Azure Entra (formerly Azure AD) client secrets
// by checking format compliance. It NEVER logs or persists raw secret values.
//
// Note: This is a format-check verifier; it performs no live verification.
// The result is therefore always StatusUnverified. Live verification would
// require an OAuth2 client credentials flow with the associated client_id and
// tenant_id, which are not available from the secret alone.
type EntraVerifier struct{}

func init() {
	verifier.Register(&EntraVerifier{})
}

// Type returns the detector ID this verifier handles.
func (v *EntraVerifier) Type() string {
	return entraDetectorID
}

// Verify checks if the detected Azure Entra client secret has a valid format.
// Raw contains the secret value.
func (v *EntraVerifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	secret := string(raw.Raw)
	if secret == "" {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty secret",
		}
	}

	if !entraSecretPattern.MatchString(secret) {
		slog.DebugContext(
			ctx, "azure entra verifier: secret does not match expected format",
			slog.Int("length", len(secret)),
		)
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (does not match Azure Entra client secret format); live verification not supported",
		}
	}

	slog.DebugContext(
		ctx, "azure entra verifier: secret format is valid",
		slog.Int("length", len(secret)),
	)

	return finding.VerificationResult{
		Status:  finding.StatusUnverified,
		Message: "format valid; live verification not supported (requires OAuth2 flow with client_id and tenant_id)",
	}
}
