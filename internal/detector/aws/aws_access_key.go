// Package aws provides AWS-related secret detectors.
package aws

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var accessKeyIDPattern = regexp.MustCompile(`(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}`)

// AccessKeyID detects AWS Access Key IDs.
type AccessKeyID struct{}

func (d *AccessKeyID) ID() string { return "aws-access-key-id" }

func (d *AccessKeyID) Description() string { return "AWS Access Key ID" }

func (d *AccessKeyID) Keywords() []string { return []string{"AKIA", "ABIA", "ACCA", "ASIA"} }

func (d *AccessKeyID) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for AWS Access Key ID patterns.
func (d *AccessKeyID) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := accessKeyIDPattern.FindAll(data, -1)
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
	detector.Register(&AccessKeyID{})
}
