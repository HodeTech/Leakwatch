// Package dbconn provides a detector for database connection strings.
package dbconn

import (
	"context"
	"regexp"
	"strings"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var connStringPattern = regexp.MustCompile(`(postgres|mysql|mongodb(\+srv)?|redis)://[^\s'"]{10,}`)

// ConnectionString detects database connection strings containing credentials.
type ConnectionString struct{}

func (d *ConnectionString) ID() string          { return "database-connection-string" }
func (d *ConnectionString) Description() string  { return "Database Connection String" }
func (d *ConnectionString) Keywords() []string {
	return []string{"postgres://", "mysql://", "mongodb://", "mongodb+srv://", "redis://"}
}
func (d *ConnectionString) Severity() finding.Severity { return finding.SeverityCritical }

// Scan scans the given data for database connection string patterns.
// The password portion of the URL is redacted in the finding output.
func (d *ConnectionString) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := connStringPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redactPassword(string(match)),
		})
	}
	return findings
}

// redactPassword masks the password portion in a database connection URL.
// Input format: scheme://user:password@host/db
// Output format: scheme://user:****@host/db
func redactPassword(url string) string {
	// Find the :// separator.
	schemeEnd := strings.Index(url, "://")
	if schemeEnd == -1 {
		return url
	}
	authority := url[schemeEnd+3:]

	// Find the @ that separates userinfo from host.
	atIdx := strings.Index(authority, "@")
	if atIdx == -1 {
		// No credentials in URL; redact everything after scheme.
		return url[:schemeEnd+3] + "****"
	}

	userinfo := authority[:atIdx]
	rest := authority[atIdx:] // includes the @

	// Find the colon separating user from password.
	colonIdx := strings.Index(userinfo, ":")
	if colonIdx == -1 {
		// No password found; return as-is with host redacted minimally.
		return url[:schemeEnd+3] + userinfo + "****"
	}

	return url[:schemeEnd+3] + userinfo[:colonIdx+1] + "****" + rest
}

func init() {
	detector.Register(&ConnectionString{})
}
