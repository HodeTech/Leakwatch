// Package vault provides a HashiCorp Vault Token secret detector.
package vault

import (
	"bytes"
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var vaultTokenPattern = regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{24,}`)

// Detector detects HashiCorp Vault Tokens.
type Detector struct{}

// ID returns the unique identifier of the HashiCorp Vault Token detector.
func (d *Detector) ID() string { return "hashicorp-vault-token" }

// Description returns a human-readable description of the HashiCorp Vault Token detector.
func (d *Detector) Description() string { return "HashiCorp Vault Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for HashiCorp Vault Token detection.
func (d *Detector) Keywords() []string { return []string{"hvs.", "VAULT_TOKEN", "vault_token"} }

// Severity returns the default severity level for HashiCorp Vault Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for HashiCorp Vault Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := vaultTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		redacted := "hvs.****" + string(match[len(match)-4:])
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        bytes.Clone(match),
			Redacted:   redacted,
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
