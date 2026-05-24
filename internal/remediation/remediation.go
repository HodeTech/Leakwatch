// Package remediation provides actionable guidance for rotating or revoking
// detected secrets. Each detector ID can have a registered Remediation that
// is attached to findings via EnrichFindings.
package remediation

import (
	"sync"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	mu       sync.RWMutex
	registry = make(map[string]finding.Remediation)
)

// Register associates a Remediation with a detector ID.
// If the same detector ID is registered again, the previous entry is overwritten.
func Register(detectorID string, r finding.Remediation) {
	mu.Lock()
	defer mu.Unlock()
	registry[detectorID] = r
}

// Get returns the Remediation for the given detector ID, or nil if none is registered.
func Get(detectorID string) *finding.Remediation {
	mu.RLock()
	defer mu.RUnlock()
	r, ok := registry[detectorID]
	if !ok {
		return nil
	}
	// Return a copy to prevent callers from mutating the registry entry.
	cp := r
	return &cp
}

// EnrichFindings returns a new slice of findings where each finding whose
// DetectorID has a registered remediation gets that remediation attached.
// The input slice is never mutated.
func EnrichFindings(findings []finding.Finding) []finding.Finding {
	mu.RLock()
	defer mu.RUnlock()

	out := make([]finding.Finding, len(findings))
	copy(out, findings)

	for i := range out {
		if r, ok := registry[out[i].DetectorID]; ok {
			cp := r
			out[i].Remediation = &cp
		}
	}
	return out
}

// Reset clears all registered remediations. For testing only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	registry = make(map[string]finding.Remediation)
}
