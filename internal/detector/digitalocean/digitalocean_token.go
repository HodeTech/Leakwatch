// Package digitalocean provides a DigitalOcean Personal Access Token secret detector.
package digitalocean

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var digitaloceanTokenPattern = regexp.MustCompile(`dop_v1_[a-f0-9]{64}`)

// Detector detects DigitalOcean Personal Access Tokens.
type Detector struct{}

func (d *Detector) ID() string          { return "digitalocean-token" }
func (d *Detector) Description() string { return "DigitalOcean Personal Access Token" }
func (d *Detector) Keywords() []string  { return []string{"dop_v1_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for DigitalOcean Personal Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := digitaloceanTokenPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		raw := string(match)
		redacted := "dop_v1_****" + raw[len(raw)-4:]
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redacted,
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
