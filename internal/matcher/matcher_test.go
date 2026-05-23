package matcher

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubDetector struct {
	id       string
	keywords []string
}

func (d *stubDetector) ID() string                                             { return d.id }
func (d *stubDetector) Description() string                                    { return d.id }
func (d *stubDetector) Keywords() []string                                     { return d.keywords }
func (d *stubDetector) Scan(_ context.Context, _ []byte) []detector.RawFinding { return nil }
func (d *stubDetector) Severity() finding.Severity                             { return finding.SeverityLow }

func detectorIDs(dets []detector.Detector) []string {
	ids := make([]string, len(dets))
	for i, d := range dets {
		ids[i] = d.ID()
	}
	return ids
}

func TestMatch_KeywordPresent_ReturnsDetector(t *testing.T) {
	m := New([]detector.Detector{
		&stubDetector{id: "aws", keywords: []string{"AKIA"}},
	})

	result := m.Match([]byte("found AKIAIOSFODNN7EXAMPLE here"))
	require.Len(t, result, 1)
	assert.Equal(t, "aws", result[0].ID())
}

func TestMatch_KeywordAbsent_ReturnsEmpty(t *testing.T) {
	m := New([]detector.Detector{
		&stubDetector{id: "aws", keywords: []string{"AKIA"}},
	})

	result := m.Match([]byte("no secrets here"))
	assert.Empty(t, result)
}

func TestMatch_CaseInsensitive_MatchesKeyword(t *testing.T) {
	m := New([]detector.Detector{
		&stubDetector{id: "generic", keywords: []string{"api_key"}},
	})

	result := m.Match([]byte("API_KEY=something"))
	require.Len(t, result, 1)
	assert.Equal(t, "generic", result[0].ID())
}

func TestMatch_MultipleDetectors_ReturnsOnlyMatched(t *testing.T) {
	m := New([]detector.Detector{
		&stubDetector{id: "aws", keywords: []string{"AKIA"}},
		&stubDetector{id: "github", keywords: []string{"ghp_", "gho_"}},
		&stubDetector{id: "slack", keywords: []string{"xoxb-", "xoxp-"}},
	})

	result := m.Match([]byte("token: ghp_abc123"))
	require.Len(t, result, 1)
	assert.Equal(t, "github", result[0].ID())
}

func TestMatch_MultipleKeywordsHit_ReturnsUniqueDetectors(t *testing.T) {
	m := New([]detector.Detector{
		&stubDetector{id: "aws", keywords: []string{"AKIA", "ASIA"}},
	})

	result := m.Match([]byte("AKIATEST ASIATEST"))
	require.Len(t, result, 1)
	assert.Equal(t, "aws", result[0].ID())
}

func TestMatch_NoKeywordsDetector_AlwaysIncluded(t *testing.T) {
	m := New([]detector.Detector{
		&stubDetector{id: "aws", keywords: []string{"AKIA"}},
		&stubDetector{id: "catchall", keywords: nil}, // no keywords
	})

	result := m.Match([]byte("no secrets at all"))
	ids := detectorIDs(result)
	assert.Contains(t, ids, "catchall")
	assert.NotContains(t, ids, "aws")
}

func TestMatch_EmptyData_ReturnsOnlyNoKeywordDetectors(t *testing.T) {
	m := New([]detector.Detector{
		&stubDetector{id: "aws", keywords: []string{"AKIA"}},
		&stubDetector{id: "catchall", keywords: nil},
	})

	result := m.Match([]byte{})
	ids := detectorIDs(result)
	assert.Contains(t, ids, "catchall")
	assert.NotContains(t, ids, "aws")
}

func TestNew_NoDetectors_ReturnsEmptyMatcher(t *testing.T) {
	m := New(nil)
	result := m.Match([]byte("anything"))
	assert.Empty(t, result)
}

// TestMatch_ConcurrentCallers_ReturnsAllMatches is the regression test for the
// Aho-Corasick data race (ENG-C-01). A single Matcher is shared across many
// goroutines, mirroring how the engine queries one matcher from every worker.
// The underlying ahocorasick library's plain Match() mutates shared trie
// counters and is not thread-safe: concurrent calls can silently drop matches.
// Match now delegates to MatchThreadSafe, so every concurrent call must still
// return the complete detector set.
//
// Run with -race; with the old Match() this test would trip the race detector
// and/or return short results. All keywords are fake fixtures, not real secrets.
func TestMatch_ConcurrentCallers_ReturnsAllMatches(t *testing.T) {
	keywords := []string{
		"akia_fake", "ghp_fake", "xoxb_fake", "sk_fake", "aiza_fake",
		"glpat_fake", "npm_fake", "dop_fake", "sq0_fake", "shppa_fake",
	}
	dets := make([]detector.Detector, len(keywords))
	for i, kw := range keywords {
		dets[i] = &stubDetector{id: kw, keywords: []string{kw}}
	}
	m := New(dets)

	// Data containing every keyword once; a correct match returns all detectors.
	var sb strings.Builder
	for _, kw := range keywords {
		fmt.Fprintf(&sb, "token_%s ", kw)
	}
	data := []byte(sb.String())

	want := append([]string(nil), keywords...)
	sort.Strings(want)

	const goroutines = 32
	const iterations = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				got := detectorIDs(m.Match(data))
				sort.Strings(got)
				if len(got) != len(want) {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("got %d matches, want %d", len(got), len(want)))
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	assert.Empty(t, failures, "concurrent Match calls must never drop detector matches")
}

func BenchmarkMatch_40Keywords(b *testing.B) {
	dets := make([]detector.Detector, 20)
	for i := range dets {
		dets[i] = &stubDetector{
			id:       "det-" + string(rune('a'+i)),
			keywords: []string{"keyword" + string(rune('a'+i)), "pattern" + string(rune('a'+i))},
		}
	}
	m := New(dets)
	// Data contains "keyworda" which matches the first detector's keyword.
	data := []byte("this text contains keyworda somewhere in a large file with lots of content")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(data)
	}
}
