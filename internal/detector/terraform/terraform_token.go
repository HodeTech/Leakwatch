// Package terraform provides a Terraform Cloud/Enterprise API Token secret detector.
package terraform

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var terraformTokenPattern = regexp.MustCompile(`[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{67,}`)

// Detector detects Terraform Cloud/Enterprise API Tokens.
type Detector struct{}

// ID returns the unique identifier of the Terraform Cloud Token detector.
func (d *Detector) ID() string { return "terraform-cloud-token" }

// Description returns a human-readable description of the Terraform Cloud Token detector.
func (d *Detector) Description() string { return "Terraform Cloud/Enterprise API Token" }

// Keywords returns the Aho-Corasick pre-filter keywords for Terraform Cloud Token detection.
func (d *Detector) Keywords() []string {
	return []string{"atlasv1", "terraform", "TF_TOKEN"}
}

// Severity returns the default severity level for Terraform Cloud Token findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Terraform Cloud/Enterprise API Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := terraformTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   detector.RedactBytes(match),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
