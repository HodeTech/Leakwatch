package engine

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/source"
	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock Source ---

type mockSource struct {
	chunks []source.Chunk
}

func (m *mockSource) Type() string    { return "mock" }
func (m *mockSource) Validate() error { return nil }
func (m *mockSource) Chunks(_ context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, len(m.chunks))
	for _, c := range m.chunks {
		ch <- c
	}
	close(ch)
	return ch
}

// --- Mock Detector ---

type mockDetector struct {
	id       string
	keywords []string
	findings []detector.RawFinding
	severity finding.Severity
}

func (m *mockDetector) ID() string                                             { return m.id }
func (m *mockDetector) Description() string                                    { return "mock " + m.id }
func (m *mockDetector) Keywords() []string                                     { return m.keywords }
func (m *mockDetector) Severity() finding.Severity                             { return m.severity }
func (m *mockDetector) Scan(_ context.Context, _ []byte) []detector.RawFinding { return m.findings }

var fixedClock = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

// --- Tests ---

func TestScan_SingleChunkSingleDetector_ReturnsOneFinding(t *testing.T) {
	src := &mockSource{
		chunks: []source.Chunk{
			{
				Data:           []byte("AKIAIOSFODNN7TESTKEY1"),
				SourceMetadata: finding.SourceMetadata{SourceType: "filesystem", FilePath: "config.yaml"},
			},
		},
	}

	det := &mockDetector{
		id:       "test-detector",
		severity: finding.SeverityCritical,
		findings: []detector.RawFinding{
			{DetectorID: "test-detector", Raw: []byte("AKIAIOSFODNN7TESTKEY1"), Redacted: "AKIA****KEY1"},
		},
	}

	eng := New(Config{Concurrency: 2, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "test-detector", result.Findings[0].DetectorID)
	assert.Equal(t, "AKIA****KEY1", result.Findings[0].Redacted)
	assert.Equal(t, finding.SeverityCritical, result.Findings[0].Severity)
	assert.NotEmpty(t, result.Findings[0].ID)
	assert.Empty(t, result.Findings[0].Raw)
	assert.Equal(t, 1, result.ScannedChunks)
	assert.False(t, result.Interrupted)
}

func TestScan_EmptySource_ReturnsNoFindings(t *testing.T) {
	src := &mockSource{chunks: nil}
	det := &mockDetector{id: "det", findings: nil}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	assert.Empty(t, result.Findings)
	assert.Equal(t, 0, result.ScannedChunks)
}

func TestScan_ShowRawEnabled_IncludesRawContent(t *testing.T) {
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: []byte("secret"), SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}

	det := &mockDetector{
		id:       "det",
		findings: []detector.RawFinding{{DetectorID: "det", Raw: []byte("secret-value"), Redacted: "sec***"}},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, ShowRaw: true, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, "secret-value", result.Findings[0].Raw)
}

func TestScan_EntropyEnabled_CalculatesEntropy(t *testing.T) {
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: []byte("data"), SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}

	det := &mockDetector{
		id:       "det",
		findings: []detector.RawFinding{{DetectorID: "det", Raw: []byte("aB3kL9mN2pQ7rT4xYz"), Redacted: "aB3k****T4xYz"}},
	}

	eng := New(Config{
		Concurrency:      1,
		Detectors:        []detector.Detector{det},
		EnableEntropy:    true,
		EntropyThreshold: 4.0,
		Clock:            fixedClock,
	})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Greater(t, result.Findings[0].Entropy, 0.0)
}

func TestScan_CancelledContext_ReturnsInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	src := &mockSource{
		chunks: []source.Chunk{
			{Data: []byte("data"), SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}

	det := &mockDetector{id: "det", findings: nil}
	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(ctx, src)
	assert.Error(t, err)
	assert.True(t, result.Interrupted)
}

func TestScan_MultipleDetectors_ReturnsAllFindings(t *testing.T) {
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: []byte("data"), SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}

	det1 := &mockDetector{id: "det-1", findings: []detector.RawFinding{{DetectorID: "det-1", Raw: []byte("s1"), Redacted: "r1"}}}
	det2 := &mockDetector{id: "det-2", findings: []detector.RawFinding{{DetectorID: "det-2", Raw: []byte("s2"), Redacted: "r2"}}}

	eng := New(Config{Concurrency: 2, Detectors: []detector.Detector{det1, det2}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	assert.Len(t, result.Findings, 2)
}

func TestScan_ComputesLineNumber(t *testing.T) {
	// "AKIATESTKEY" sits on line 2 of the chunk.
	data := []byte("first line\nKEY = \"AKIATESTKEY\"\nthird line\n")
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: data, SourceMetadata: finding.SourceMetadata{FilePath: "config.txt"}},
		},
	}
	det := &mockDetector{
		id:       "det",
		findings: []detector.RawFinding{{DetectorID: "det", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"}},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, 2, result.Findings[0].SourceMetadata.Line, "match is on the second line")
}

func TestScan_LineNumber_FirstLineIsOne(t *testing.T) {
	data := []byte("AKIATESTKEY at the very top\nsecond line\n")
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: data, SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}
	det := &mockDetector{
		id:       "det",
		findings: []detector.RawFinding{{DetectorID: "det", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"}},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, 1, result.Findings[0].SourceMetadata.Line)
}

func TestScan_SourceProvidedLine_NotOverwritten(t *testing.T) {
	data := []byte("line1\nAKIATESTKEY\nline3\n")
	src := &mockSource{
		chunks: []source.Chunk{
			// Source already supplies a line number (e.g. a future line-aware source).
			{Data: data, SourceMetadata: finding.SourceMetadata{FilePath: "f.txt", Line: 42}},
		},
	}
	det := &mockDetector{
		id:       "det",
		findings: []detector.RawFinding{{DetectorID: "det", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"}},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, 42, result.Findings[0].SourceMetadata.Line, "engine must not overwrite a source-provided line")
}

func TestScan_RepeatedSecret_DistinctLinesAndIDs(t *testing.T) {
	// Same secret bytes on lines 1 and 3. The detector emits one RawFinding per
	// occurrence (as regexp.FindAll would). Each must resolve to its own line
	// and therefore its own ID — regression test for the "all repeats collapse
	// onto the first occurrence's line" bug.
	data := []byte("k=AKIATESTKEY\nx\nk=AKIATESTKEY\n")
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: data, SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}
	det := &mockDetector{
		id: "det",
		findings: []detector.RawFinding{
			{DetectorID: "det", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"},
			{DetectorID: "det", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"},
		},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 2)

	lines := []int{result.Findings[0].SourceMetadata.Line, result.Findings[1].SourceMetadata.Line}
	assert.ElementsMatch(t, []int{1, 3}, lines, "the two occurrences must report distinct lines")
	assert.NotEqual(t, result.Findings[0].ID, result.Findings[1].ID, "distinct lines must yield distinct IDs")
}

func TestScan_RepeatedSecret_FirstIgnored_SecondReported(t *testing.T) {
	// Line 1 carries an ignore marker; line 3 is a real leak. The real leak
	// MUST still be reported — regression test for the false-negative where an
	// early ignored copy suppressed a later genuine secret.
	data := []byte("k=AKIATESTKEY # leakwatch:ignore\nx\nk=AKIATESTKEY\n")
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: data, SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}
	det := &mockDetector{
		id: "aws-access-key-id",
		findings: []detector.RawFinding{
			{DetectorID: "aws-access-key-id", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"},
			{DetectorID: "aws-access-key-id", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"},
		},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "the un-ignored occurrence on line 3 must be reported")
	assert.Equal(t, 3, result.Findings[0].SourceMetadata.Line)
}

func TestScan_RepeatedSecret_LateIgnore_OnlyThatOneSuppressed(t *testing.T) {
	// Line 1 is a real leak; line 2 carries the ignore marker. Exactly one
	// finding (line 1) must remain.
	data := []byte("k=AKIATESTKEY\nk=AKIATESTKEY # leakwatch:ignore\n")
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: data, SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}
	det := &mockDetector{
		id: "aws-access-key-id",
		findings: []detector.RawFinding{
			{DetectorID: "aws-access-key-id", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"},
			{DetectorID: "aws-access-key-id", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"},
		},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	assert.Equal(t, 1, result.Findings[0].SourceMetadata.Line)
}

func TestScan_InlineIgnore_GenericMarker_SkipsFinding(t *testing.T) {
	data := []byte("safe line\n" + `KEY = "AKIATESTKEY" # leakwatch:ignore` + "\n")
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: data, SourceMetadata: finding.SourceMetadata{FilePath: "config.txt"}},
		},
	}
	det := &mockDetector{
		id:       "aws-access-key-id",
		findings: []detector.RawFinding{{DetectorID: "aws-access-key-id", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"}},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	assert.Empty(t, result.Findings, "finding on a generic inline-ignore line must be skipped")
}

func TestScan_InlineIgnore_DetectorSpecific(t *testing.T) {
	// Marker targets a different detector, so the finding must remain.
	data := []byte(`KEY = "AKIATESTKEY" # leakwatch:ignore:some-other-detector` + "\n")
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: data, SourceMetadata: finding.SourceMetadata{FilePath: "config.txt"}},
		},
	}
	det := &mockDetector{
		id:       "aws-access-key-id",
		findings: []detector.RawFinding{{DetectorID: "aws-access-key-id", Raw: []byte("AKIATESTKEY"), Redacted: "AKIA****"}},
	}

	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "marker for a different detector must not suppress this finding")

	// Same line, matching detector ID — now it should be skipped.
	det.id = "some-other-detector"
	det.findings[0].DetectorID = "some-other-detector"
	eng2 := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})
	result2, err := eng2.Scan(context.Background(), src)
	require.NoError(t, err)
	assert.Empty(t, result2.Findings, "marker matching the detector ID must suppress the finding")
}

// keywordDetector is a detector whose ID and single keyword are identical. Its
// Scan emits exactly one RawFinding per occurrence of that keyword in the chunk
// data. Combined with the Aho-Corasick pre-filter (which decides whether the
// detector runs at all for a chunk), this lets a concurrency test assert the
// full expected finding set: a dropped or misrouted keyword match anywhere in
// the pipeline shows up as a missing finding.
//
// All values are fake, redacted-style fixtures — no real secrets.
type keywordDetector struct {
	keyword string
}

func (d *keywordDetector) ID() string                 { return d.keyword }
func (d *keywordDetector) Description() string        { return "keyword detector " + d.keyword }
func (d *keywordDetector) Keywords() []string         { return []string{d.keyword} }
func (d *keywordDetector) Severity() finding.Severity { return finding.SeverityHigh }

func (d *keywordDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	kw := []byte(d.keyword)
	var out []detector.RawFinding
	for from := 0; ; {
		idx := bytes.Index(data[from:], kw)
		if idx < 0 {
			break
		}
		out = append(out, detector.RawFinding{
			DetectorID: d.keyword,
			Raw:        kw,
			Redacted:   d.keyword[:1] + "****",
		})
		from += idx + len(kw)
	}
	return out
}

// TestScan_ConcurrentWorkers_ReturnsAllFindings is the regression test for the
// Aho-Corasick data race (ENG-C-01). The engine shares one *matcher.Matcher
// across all workers and queries it concurrently. The underlying ahocorasick
// library's plain Match() mutates shared trie counters and is not thread-safe;
// under concurrency it can silently drop matches, which would surface here as
// fewer findings than expected. With MatchThreadSafe() the full set is returned.
//
// Run with -race; with the old Match() this test would also trip the race
// detector. Concurrency is set to 8 and the input is many chunks, each carrying
// every detector's keyword, so parallel workers genuinely contend on the shared
// matcher.
func TestScan_ConcurrentWorkers_ReturnsAllFindings(t *testing.T) {
	// Fake keyword fixtures, one detector each. Distinct, non-overlapping tokens.
	keywords := []string{
		"akia_fake", "ghp_fake", "xoxb_fake", "sk_fake", "aiza_fake",
		"glpat_fake", "npm_fake", "dop_fake", "sq0_fake", "shppa_fake",
	}
	dets := make([]detector.Detector, len(keywords))
	for i, kw := range keywords {
		dets[i] = &keywordDetector{keyword: kw}
	}

	// Build a chunk whose data contains every keyword exactly once, so each
	// chunk should yield exactly len(keywords) findings.
	var sb bytes.Buffer
	for _, kw := range keywords {
		fmt.Fprintf(&sb, "token_%s = \"value\"\n", kw)
	}
	chunkData := sb.Bytes()

	const numChunks = 200
	chunks := make([]source.Chunk, numChunks)
	for i := range chunks {
		// Each chunk gets a distinct file path so findings are distinct per chunk.
		chunks[i] = source.Chunk{
			Data: chunkData,
			SourceMetadata: finding.SourceMetadata{
				SourceType: "filesystem",
				FilePath:   fmt.Sprintf("file_%03d.txt", i),
			},
		}
	}
	src := &mockSource{chunks: chunks}

	eng := New(Config{Concurrency: 8, Detectors: dets, Clock: fixedClock})

	result, err := eng.Scan(context.Background(), src)
	require.NoError(t, err)

	// Every chunk must produce one finding per keyword.
	expected := numChunks * len(keywords)
	require.Len(t, result.Findings, expected,
		"shared matcher must not drop matches under concurrent workers")

	// Sanity: every detector ID is represented the expected number of times.
	counts := make(map[string]int)
	for _, f := range result.Findings {
		counts[f.DetectorID]++
	}
	for _, kw := range keywords {
		assert.Equal(t, numChunks, counts[kw],
			"detector %q must fire on every chunk", kw)
	}
}

func TestScan_SameInput_ReturnsDeterministicID(t *testing.T) {
	src := &mockSource{
		chunks: []source.Chunk{
			{Data: []byte("data"), SourceMetadata: finding.SourceMetadata{FilePath: "f.txt"}},
		},
	}

	det := &mockDetector{id: "det", findings: []detector.RawFinding{{DetectorID: "det", Raw: []byte("val"), Redacted: "v**"}}}
	eng := New(Config{Concurrency: 1, Detectors: []detector.Detector{det}, Clock: fixedClock})

	r1, _ := eng.Scan(context.Background(), src)
	r2, _ := eng.Scan(context.Background(), src)

	require.Len(t, r1.Findings, 1)
	require.Len(t, r2.Findings, 1)
	assert.Equal(t, r1.Findings[0].ID, r2.Findings[0].ID, "same input must produce same ID")
}
