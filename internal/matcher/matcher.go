// Package matcher provides Aho-Corasick based keyword pre-filtering.
// It builds an automaton from detector keywords and efficiently identifies
// which detectors are relevant for a given chunk of data.
package matcher

import (
	"bytes"
	"strings"

	"github.com/cloudflare/ahocorasick"

	"github.com/cemililik/leakwatch/internal/detector"
)

// Matcher performs Aho-Corasick keyword pre-filtering to determine which
// detectors should be run against a given chunk of data.
type Matcher struct {
	machine      *ahocorasick.Matcher
	keywords     []string
	keywordToDet map[string][]string // keyword -> list of detector IDs
	allDetectors map[string]detector.Detector
	noKeywordIDs []string // detector IDs with no keywords (always run)
}

// New builds an Aho-Corasick automaton from the given detectors' keywords.
// Detectors with no keywords are always included in match results.
func New(detectors []detector.Detector) *Matcher {
	m := &Matcher{
		keywordToDet: make(map[string][]string),
		allDetectors: make(map[string]detector.Detector),
	}

	var keywords []string
	seen := make(map[string]bool)
	for _, det := range detectors {
		m.allDetectors[det.ID()] = det

		kws := det.Keywords()
		if len(kws) == 0 {
			m.noKeywordIDs = append(m.noKeywordIDs, det.ID())
			continue
		}

		for _, kw := range kws {
			lower := strings.ToLower(kw)
			m.keywordToDet[lower] = append(m.keywordToDet[lower], det.ID())
			if seen[lower] {
				continue
			}
			seen[lower] = true
			keywords = append(keywords, lower)
		}
	}

	m.keywords = keywords
	if len(keywords) > 0 {
		m.machine = ahocorasick.NewStringMatcher(keywords)
	}

	return m
}

// Match returns the subset of detectors whose keywords appear in the data.
// Detectors without keywords are always included.
//
// Match is safe for concurrent use by multiple goroutines: a single Matcher is
// shared across all engine workers, so the underlying Aho-Corasick automaton is
// queried via the thread-safe MatchThreadSafe entry point (see below). The
// non-thread-safe Match method of the ahocorasick library mutates shared trie
// node counters and would otherwise cause a data race and silently drop matches
// (missed secrets) under concurrent calls.
func (m *Matcher) Match(data []byte) []detector.Detector {
	matchedIDs := make(map[string]bool)

	// Always include detectors with no keywords.
	for _, id := range m.noKeywordIDs {
		matchedIDs[id] = true
	}

	if m.machine == nil {
		// No keywords registered at all; return all detectors.
		result := make([]detector.Detector, 0, len(m.allDetectors))
		for _, det := range m.allDetectors {
			result = append(result, det)
		}
		return result
	}

	// Run Aho-Corasick on lowercased data. MatchThreadSafe (not Match) is used
	// because this Matcher is shared across concurrent engine workers; the plain
	// Match method is documented by the library as not thread-safe.
	lower := bytes.ToLower(data)
	hits := m.machine.MatchThreadSafe(lower)

	for _, idx := range hits {
		// idx is an index into the keyword dictionary the automaton was built
		// from (m.keywords), so it is always in range. The bounds check is a
		// silent defensive guard; it must not log on this hot path (called per
		// chunk per worker) to avoid log spam.
		if idx < len(m.keywords) {
			kw := m.keywords[idx]
			for _, detID := range m.keywordToDet[kw] {
				matchedIDs[detID] = true
			}
		}
	}

	result := make([]detector.Detector, 0, len(matchedIDs))
	for id := range matchedIDs {
		if det, ok := m.allDetectors[id]; ok {
			result = append(result, det)
		}
	}
	return result
}
