package verifier

import (
	"sort"
	"sync"
)

var (
	mu        sync.RWMutex
	verifiers = make(map[string]Verifier)
)

// Register adds a verifier to the global registry.
// Each verifier package calls this function in its init() function.
// Panics if a verifier with the same Type() is already registered.
func Register(v Verifier) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := verifiers[v.Type()]; exists {
		panic("duplicate verifier type: " + v.Type())
	}
	verifiers[v.Type()] = v
}

// Get returns the verifier registered for the given detector ID.
func Get(detectorID string) (Verifier, bool) {
	mu.RLock()
	defer mu.RUnlock()
	v, ok := verifiers[detectorID]
	return v, ok
}

// All returns all registered verifiers sorted by Type().
func All() []Verifier {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Verifier, 0, len(verifiers))
	for _, v := range verifiers {
		result = append(result, v)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Type() < result[j].Type()
	})
	return result
}

// Reset clears all registered verifiers. Only for use in tests.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	verifiers = make(map[string]Verifier)
}
