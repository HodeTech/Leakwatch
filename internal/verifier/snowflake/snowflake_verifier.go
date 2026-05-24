// Package snowflake provides a verifier for Snowflake credentials.
// Live verification requires a JDBC/ODBC connection, so this verifier
// performs format validation only and never reports a secret as active or
// inactive without contacting the provider.
package snowflake

import (
	"bytes"
	"context"
	"log/slog"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const detectorID = "snowflake-credentials"

// minPasswordLen is the minimum length a Snowflake password must have to be
// considered a plausible credential. Snowflake requires passwords of at least
// eight characters, so anything shorter is almost certainly a false positive.
const minPasswordLen = 8

// snowflakeHost is the host substring that identifies a Snowflake connection
// string. The detector captures the full connection string in RawV2.
var snowflakeHost = []byte("snowflakecomputing.com")

// Verifier checks whether Snowflake credentials have a plausible format.
// It NEVER logs or persists raw password values, and it NEVER reports a
// credential as active/inactive because no live verification is performed.
type Verifier struct{}

func init() {
	verifier.Register(&Verifier{})
}

// Type returns the detector ID this verifier handles.
func (v *Verifier) Type() string {
	return detectorID
}

// Verify performs a format check on the detected Snowflake credentials.
// Raw contains the password value and RawV2 contains the full connection
// string. Because live verification requires a database connection, the
// result is always StatusUnverified: a valid format does not prove the
// credential is active, and an invalid format does not prove it is inactive.
func (v *Verifier) Verify(ctx context.Context, raw detector.RawFinding) finding.VerificationResult {
	password := raw.Raw
	if len(password) == 0 {
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "empty credentials",
		}
	}

	if len(password) < minPasswordLen {
		slog.DebugContext(ctx, "snowflake verifier: password too short for valid format")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (password too short); live verification not supported",
		}
	}

	// The detector captures the surrounding connection string in RawV2; a
	// genuine Snowflake credential references the snowflakecomputing.com host.
	if len(raw.RawV2) > 0 && !bytes.Contains(raw.RawV2, snowflakeHost) {
		slog.DebugContext(ctx, "snowflake verifier: connection string missing snowflake host")
		return finding.VerificationResult{
			Status:  finding.StatusUnverified,
			Message: "format invalid (not a Snowflake connection string); live verification not supported",
		}
	}

	slog.DebugContext(ctx, "snowflake verifier: credentials format validated")

	return finding.VerificationResult{
		Status:  finding.StatusUnverified,
		Message: "format valid; live verification not supported (requires database connection)",
	}
}
