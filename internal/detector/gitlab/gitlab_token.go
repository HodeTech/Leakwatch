// Package gitlab provides a GitLab Personal Access Token secret detector.
package gitlab

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var gitlabPATPattern = regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20}`)

// Detector detects GitLab Personal Access Tokens.
type Detector struct{}

func (d *Detector) ID() string { return "gitlab-pat" }

func (d *Detector) Description() string { return "GitLab Personal Access Token" }

func (d *Detector) Keywords() []string { return []string{"glpat-"} }

func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for GitLab Personal Access Token patterns.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := gitlabPATPattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   "glpat-****" + string(match[len(match)-4:]),
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
