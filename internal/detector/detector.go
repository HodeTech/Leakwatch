// Package detector defines secret detection interfaces.
package detector

import (
	"context"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Detector represents a component that detects a specific secret type.
type Detector interface {
	// ID returns the unique identifier (e.g., "aws-access-key-id").
	ID() string

	// Description returns a human-readable description.
	Description() string

	// Keywords returns Aho-Corasick pre-filter keywords.
	// If empty, pre-filtering is skipped and regex is applied to every chunk.
	Keywords() []string

	// Scan scans the given data and returns potential secret findings.
	Scan(ctx context.Context, data []byte) []RawFinding

	// Severity returns the default severity for findings from this detector.
	Severity() finding.Severity
}

// RawFinding represents an unverified raw finding.
type RawFinding struct {
	DetectorID string
	Raw        []byte
	RawV2      []byte
	Redacted   string
	ExtraData  map[string]string
}
