// Package generic provides general-purpose secret detectors.
package generic

import (
	"bytes"
	"context"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/entropy"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var apiKeyPattern = regexp.MustCompile(`(?i)(api[_\-]?key|api[_\-]?secret|secret[_\-]?key|x[_\-]?apisix[_\-]?key|apisix[_\-]?key|apisix[_\-]?admin[_\-]?key)[ \t]*[:=][ \t]*['"]?([a-zA-Z0-9/\-_]{16,64})['"]?`)

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

		// Skip placeholder/example values
		if isPlaceholder(value) {
			continue
		}

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        value,
			Redacted:   detector.RedactBytes(value),
			ExtraData: map[string]string{
				"key_name": string(match[1]),
			},
		})
	}
	return findings
}

// placeholderPatterns are common dummy values used in example configs.
var placeholderPatterns = [][]byte{
	[]byte("change_me"),
	[]byte("changeme"),
	[]byte("your_key_here"),
	[]byte("your-key-here"),
	[]byte("replace_me"),
	[]byte("xxxxxxxx"),
	[]byte("TODO"),
	[]byte("FIXME"),
	[]byte("placeholder"),
	[]byte("example"),
	[]byte("_API_KEY"),
	[]byte("_SECRET_KEY"),
	[]byte("_API_SECRET"),
}

func isPlaceholder(value []byte) bool {
	lower := bytes.ToLower(value)
	for _, p := range placeholderPatterns {
		if bytes.Contains(lower, p) {
			return true
		}
	}
	return false
}

func init() {
	detector.Register(&APIKeyDetector{})
}
