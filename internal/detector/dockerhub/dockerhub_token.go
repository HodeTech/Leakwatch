// Package dockerhub provides a Docker Hub Personal Access Token secret detector.
package dockerhub

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var dockerhubPATPattern = regexp.MustCompile(`dckr_pat_[A-Za-z0-9_-]{27,}`)

// Detector detects Docker Hub Personal Access Tokens.
type Detector struct{}

func (d *Detector) ID() string          { return "dockerhub-pat" }
func (d *Detector) Description() string { return "Docker Hub Personal Access Token" }
func (d *Detector) Keywords() []string  { return []string{"dckr_pat_"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Docker Hub Personal Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := dockerhubPATPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		raw := string(match)
		redacted := "dckr_pat_****" + raw[len(raw)-4:]
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
