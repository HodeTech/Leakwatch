package detector

import (
	"sort"
	"sync"
)

var (
	mu        sync.RWMutex
	detectors = make(map[string]Detector)
)

// Register adds a detector to the central registry.
// Each detector package calls this in its init() function.
// Panics if a duplicate ID is registered.
func Register(d Detector) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := detectors[d.ID()]; exists {
		panic("duplicate detector ID: " + d.ID())
	}
	detectors[d.ID()] = d
}

// RegisterIfAbsent registers d only if its ID is not already taken, atomically.
// It returns true when the detector was registered and false when an entry with
// the same ID already existed. Unlike Register it never panics, which makes it
// safe for runtime-supplied detectors such as user-defined custom rules.
func RegisterIfAbsent(d Detector) bool {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := detectors[d.ID()]; exists {
		return false
	}
	detectors[d.ID()] = d
	return true
}

// All returns all registered detectors sorted by ID.
func All() []Detector {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Detector, 0, len(detectors))
	for _, d := range detectors {
		result = append(result, d)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].ID() < result[j].ID()
	})
	return result
}

// Get returns the detector with the given ID.
func Get(id string) (Detector, bool) {
	mu.RLock()
	defer mu.RUnlock()
	d, ok := detectors[id]
	return d, ok
}

// Reset clears all registered detectors. For testing only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	detectors = make(map[string]Detector)
}
