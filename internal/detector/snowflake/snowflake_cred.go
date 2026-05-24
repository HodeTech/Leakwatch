// Package snowflake provides a Snowflake Connection Credentials secret detector.
package snowflake

import (
	"context"
	"regexp"
	"strings"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var snowflakeCredPattern = regexp.MustCompile(`snowflakecomputing\.com[^\s]*(?:password|pwd|PWD|PASSWORD)\s*=\s*([^&\s'"]+)`)

// Detector detects Snowflake Connection Credentials with embedded passwords.
type Detector struct{}

// ID returns the unique identifier of the Snowflake Credentials detector.
func (d *Detector) ID() string { return "snowflake-credentials" }

// Description returns a human-readable description of the Snowflake Credentials detector.
func (d *Detector) Description() string { return "Snowflake Connection Credentials" }

// Keywords returns the Aho-Corasick pre-filter keywords for Snowflake Credentials detection.
func (d *Detector) Keywords() []string {
	return []string{"snowflakecomputing"}
}

// Severity returns the default severity level for Snowflake Credentials findings.
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Snowflake connection strings containing passwords.
// The password value is extracted from the match and redacted in the finding output.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	allMatches := snowflakeCredPattern.FindAllSubmatch(data, -1)
	if len(allMatches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(allMatches))
	for _, groups := range allMatches {
		fullMatch := groups[0]
		passwordValue := groups[1]

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        passwordValue,
			RawV2:      fullMatch,
			Redacted:   redactSnowflake(string(fullMatch)),
			ExtraData: map[string]string{
				"password": string(passwordValue),
			},
		})
	}
	return findings
}

// redactSnowflake replaces the password value in the matched string with ****.
// It locates the password/pwd parameter and masks everything after the = sign.
func redactSnowflake(match string) string {
	for _, param := range []string{"PASSWORD", "password", "PWD", "pwd"} {
		idx := strings.Index(match, param+"=")
		if idx == -1 {
			idx = strings.Index(match, param+" =")
		}
		if idx == -1 {
			continue
		}
		eqIdx := strings.Index(match[idx:], "=")
		if eqIdx == -1 {
			continue
		}
		prefix := match[:idx+eqIdx+1]
		return prefix + "****"
	}
	return match
}

func init() {
	detector.Register(&Detector{})
}
