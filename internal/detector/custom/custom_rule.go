// Package custom provides a YAML-based custom rule detector.
// Users can define their own secret patterns in .leakwatch.yaml.
package custom

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/entropy"
	"github.com/cemililik/leakwatch/pkg/finding"
)

// RuleDef represents a user-defined custom detection rule from YAML config.
type RuleDef struct {
	ID          string   `yaml:"id" mapstructure:"id"`
	Description string   `yaml:"description" mapstructure:"description"`
	Regex       string   `yaml:"regex" mapstructure:"regex"`
	Keywords    []string `yaml:"keywords" mapstructure:"keywords"`
	Severity    string   `yaml:"severity" mapstructure:"severity"`
	Entropy     float64  `yaml:"entropy" mapstructure:"entropy"`
}

// CustomDetector implements detector.Detector for user-defined rules.
type CustomDetector struct {
	def     RuleDef
	pattern *regexp.Regexp
	sev     finding.Severity
}

// NewFromDef creates a CustomDetector from a RuleDef.
// Returns an error if the regex pattern is invalid.
func NewFromDef(def RuleDef) (*CustomDetector, error) {
	if def.ID == "" {
		return nil, fmt.Errorf("custom rule ID is required")
	}
	if def.Regex == "" {
		return nil, fmt.Errorf("custom rule %q: regex is required", def.ID)
	}

	pattern, err := regexp.Compile(def.Regex)
	if err != nil {
		return nil, fmt.Errorf("custom rule %q: invalid regex: %w", def.ID, err)
	}

	sev := parseSeverity(def.Severity)

	return &CustomDetector{
		def:     def,
		pattern: pattern,
		sev:     sev,
	}, nil
}

func (d *CustomDetector) ID() string          { return d.def.ID }
func (d *CustomDetector) Description() string  { return d.def.Description }
func (d *CustomDetector) Keywords() []string   { return d.def.Keywords }
func (d *CustomDetector) Severity() finding.Severity { return d.sev }

// Scan searches the data for matches against the custom regex pattern.
// If an entropy threshold is defined, matches below it are skipped.
func (d *CustomDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := d.pattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		if d.def.Entropy > 0 && entropy.Calculate(match) < d.def.Entropy {
			continue
		}

		redacted := redactMatch(match)
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redacted,
		})
	}
	return findings
}

// RegisterCustomRules parses RuleDefs, creates detectors, and registers them.
// Returns the count of successfully registered rules and any errors.
func RegisterCustomRules(rules []RuleDef) (int, []error) {
	var errs []error
	count := 0

	for _, def := range rules {
		det, err := NewFromDef(def)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		detector.Register(det)
		count++
	}

	return count, errs
}

func redactMatch(match []byte) string {
	if len(match) <= 8 {
		return "****"
	}
	return string(match[:4]) + "****" + string(match[len(match)-4:])
}

func parseSeverity(s string) finding.Severity {
	switch s {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}
