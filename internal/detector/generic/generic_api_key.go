// Package generic provides general-purpose secret detectors.
package generic

import (
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/entropy"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var apiKeyPattern = regexp.MustCompile(`(?i)(api[_\-]?key|api[_\-]?secret|secret[_\-]?key|x[_\-]?apisix[_\-]?key|apisix[_\-]?key|apisix[_\-]?admin[_\-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9/+=\-_]{16,64})['"]?`)

// APIKeyDetector detects generic API key assignments.
type APIKeyDetector struct{}

func (d *APIKeyDetector) ID() string { return "generic-api-key" }

func (d *APIKeyDetector) Description() string { return "Generic API Key" }
func (d *APIKeyDetector) Keywords() []string {
	return []string{
		"api_key", "api-key", "apikey",
		"api_secret", "api-secret", "apisecret",
		"secret_key", "secret-key", "secretkey",
		"apisix-key", "apisix_key", "x-apisix-key", "x_apisix_key", "apisix-admin-key",
	}
}
func (d *APIKeyDetector) Severity() finding.Severity { return finding.SeverityMedium }

// Scan searches the data for generic API key assignment patterns.
// Applies Shannon entropy filtering after regex matching;
// matches with entropy below 3.0 are skipped as unlikely to be real secrets.
func (d *APIKeyDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := apiKeyPattern.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		value := match[2]

		// Skip low-entropy values — unlikely to be real secrets
		if entropy.Calculate(value) < 3.0 {
			continue
		}

		redacted := redactValue(value)
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        value,
			Redacted:   redacted,
			ExtraData: map[string]string{
				"key_name": string(match[1]),
			},
		})
	}
	return findings
}

func redactValue(value []byte) string {
	if len(value) <= 8 {
		return "****"
	}
	return string(value[:4]) + "****" + string(value[len(value)-4:])
}

func init() {
	detector.Register(&APIKeyDetector{})
}
