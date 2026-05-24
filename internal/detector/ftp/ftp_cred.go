// Package ftp provides an FTP/SFTP Credentials secret detector.
package ftp

import (
	"context"
	"net/url"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var ftpCredPattern = regexp.MustCompile(`(?:s?ftps?)://[^\s'"]+:[^\s'"]+@[^\s'"]+`)

// Detector detects FTP/SFTP Credentials in connection URLs.
type Detector struct{}

// ID returns the unique identifier of the FTP Credentials detector.
func (d *Detector) ID() string { return "ftp-credentials" }

// Description returns a human-readable description of the FTP Credentials detector.
func (d *Detector) Description() string { return "FTP/SFTP Credentials" }

// Keywords returns the Aho-Corasick pre-filter keywords for FTP Credentials detection.
func (d *Detector) Keywords() []string {
	return []string{"ftp://", "sftp://", "ftps://"}
}

// Severity returns the default severity level for FTP Credentials findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for FTP/SFTP credential patterns.
// The password portion of the URL is redacted in the finding output.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := ftpCredPattern.FindAll(data, -1)
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

// redactPassword masks the password portion in an FTP/SFTP connection URL.
// Uses net/url.Parse for proper parsing, then reconstructs with masked password.
func redactPassword(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "****"
	}
	if u.User == nil {
		return raw
	}
	username := u.User.Username()
	u.User = nil
	return u.Scheme + "://" + username + ":****@" + u.Host + u.RequestURI()
}

func init() {
	detector.Register(&Detector{})
}
