// Package engine provides the Leakwatch scan engine.
package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/entropy"
	"github.com/cemililik/leakwatch/internal/filter"
	"github.com/cemililik/leakwatch/internal/matcher"
	"github.com/cemililik/leakwatch/internal/source"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const (
	// defaultEntropyThreshold is the default Shannon entropy threshold.
	defaultEntropyThreshold = 4.0

	// channelBufferMultiplier is the channel buffer size multiplier.
	channelBufferMultiplier = 2

	// hashTruncateLen is the Finding ID hash truncation length in bytes.
	// 16 bytes = 128 bits provides sufficient collision resistance.
	hashTruncateLen = 16
)

// Config holds the scan engine configuration.
type Config struct {
	Concurrency   int
	Detectors     []detector.Detector
	EnableEntropy bool
	// EntropyThreshold is display-only at the engine level. When EnableEntropy
	// is set, the engine computes Shannon entropy purely to populate
	// Finding.Entropy for reporting (see rawToFinding); it does NOT gate or drop
	// findings whose entropy falls below this value. Threshold-based gating
	// currently applies only to custom rules (handled inside their detector);
	// engine-wide entropy gating is planned and tracked separately in the docs/
	// ROADMAP. The value is defaulted to defaultEntropyThreshold in New.
	EntropyThreshold float64
	ShowRaw          bool
	Clock            func() time.Time // Optional; defaults to time.Now
	VerifierConfig   verifier.Config
	Verifiers        []verifier.Verifier
	OnlyVerified     bool             // If true, only return verified active findings
	MinSeverity      finding.Severity // Minimum severity to include in results
}

// ScanResult represents the outcome of a scan.
type ScanResult struct {
	Findings      []finding.Finding
	ScannedChunks int
	Duration      time.Duration
	Interrupted   bool
}

// Engine is the scan engine that orchestrates detection and verification.
type Engine struct {
	config   Config
	matcher  *matcher.Matcher
	verifyEn *verifier.Engine
}

// New creates a new scan engine.
// The Aho-Corasick automaton is compiled from detector keywords.
func New(cfg Config) *Engine {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	// EntropyThreshold is defaulted here for completeness, but note it is
	// display-only at the engine level (see Config.EntropyThreshold): the engine
	// never gates findings on it. Custom rules apply their own threshold.
	if cfg.EntropyThreshold <= 0 {
		cfg.EntropyThreshold = defaultEntropyThreshold
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Engine{
		config:   cfg,
		matcher:  matcher.New(cfg.Detectors),
		verifyEn: verifier.NewEngine(cfg.VerifierConfig, cfg.Verifiers),
	}
}

// Scan scans the given source and returns results.
func (e *Engine) Scan(ctx context.Context, src source.Source) (*ScanResult, error) {
	if err := src.Validate(); err != nil {
		return nil, fmt.Errorf("source validation failed: %w", err)
	}

	start := time.Now()

	slog.Info(
		"scan started",
		"source", src.Type(),
		"concurrency", e.config.Concurrency,
		"detectors", len(e.config.Detectors),
	)

	jobs := make(chan source.Chunk, e.config.Concurrency*channelBufferMultiplier)
	results := make(chan verifier.VerifyPair, e.config.Concurrency*channelBufferMultiplier)

	// Start workers.
	var wg sync.WaitGroup
	for i := 0; i < e.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.worker(ctx, jobs, results)
		}()
	}

	// Collect results (Finding + RawFinding pairs).
	//
	// Raw secret byte lifetime: each VerifyPair carries the raw secret bytes
	// (p.Raw) in memory only so that verification can re-present them to the
	// relevant API. These bytes are never logged, written to disk, or otherwise
	// persisted (per the project's secret-safety rule); they live only until
	// VerifyAll has consumed them below, after which the pairs slice goes out of
	// scope and becomes eligible for garbage collection.
	//
	// Known limitation (ENG-M-02): pairs accumulates every detected pair for the
	// whole scan before verification runs, so peak memory grows with the total
	// number of findings (raw bytes included). For very large or highly
	// secret-dense inputs this is unbounded. Streaming verification / a
	// MaxFindings cap is intentionally not implemented here yet and is tracked
	// separately; this comment documents the current behavior.
	var pairs []verifier.VerifyPair
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for p := range results {
			pairs = append(pairs, p)
		}
	}()

	// Send chunks to the jobs channel.
	// NOTE: Context cancellation during this loop depends on the source implementation
	// closing its Chunks channel promptly when ctx is cancelled. If a source blocks
	// indefinitely on send, this loop may not exit until the source returns.
	scannedChunks := 0
loop:
	for chunk := range src.Chunks(ctx) {
		select {
		case <-ctx.Done():
			break loop
		case jobs <- chunk:
			scannedChunks++
		}
	}
	close(jobs)

	// Wait for workers to finish
	wg.Wait()
	close(results)

	// Wait for collector to finish
	collectWg.Wait()

	// Run verification on collected pairs.
	findings := e.verifyEn.VerifyAll(ctx, pairs)

	// Apply post-scan filters.
	findings = e.applyFilters(findings)

	result := &ScanResult{
		Findings:      findings,
		ScannedChunks: scannedChunks,
		Duration:      time.Since(start),
		Interrupted:   ctx.Err() != nil,
	}

	slog.Info(
		"scan completed",
		"findings", len(findings),
		"chunks", scannedChunks,
		"duration", result.Duration,
		"interrupted", result.Interrupted,
	)

	if ctx.Err() != nil {
		return result, fmt.Errorf("scan interrupted: %w", ctx.Err())
	}

	return result, nil
}

// worker reads chunks from the jobs channel, runs matched detectors, and sends
// VerifyPair results. It exits cleanly when the channel is closed or context is cancelled.
func (e *Engine) worker(ctx context.Context, jobs <-chan source.Chunk, results chan<- verifier.VerifyPair) {
	for chunk := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Aho-Corasick pre-filtering: only run matched detectors.
		matchedDetectors := e.matcher.Match(chunk.Data)

		for _, det := range matchedDetectors {
			select {
			case <-ctx.Done():
				return
			default:
			}

			rawFindings := det.Scan(ctx, chunk.Data)

			// Track the search position per raw value so repeated matches of the
			// same bytes resolve to distinct offsets. Detectors emit findings in
			// left-to-right match order (regexp.FindAll guarantees this), so the
			// Nth occurrence of a raw value maps to its Nth position in the chunk.
			offsetCursor := make(map[string]int)

			for _, raw := range rawFindings {
				offset := nextMatchOffset(chunk.Data, raw.Raw, offsetCursor)
				f := e.rawToFinding(raw, chunk, det, offset)

				// Honor inline ignore markers (# leakwatch:ignore[:<id>]) on the
				// finding's source line. Skipped before verification so ignored
				// secrets never trigger a network call.
				if filter.LineHasInlineIgnore(chunk.Data, f.SourceMetadata.Line, det.ID()) {
					continue
				}

				pair := verifier.VerifyPair{Finding: f, Raw: raw}
				select {
				case <-ctx.Done():
					return
				case results <- pair:
				}
			}
		}
	}
}

// nextMatchOffset returns the byte offset of the next occurrence of raw in
// data, starting from the cursor position recorded for that raw value, and
// advances the cursor past it. This makes repeated matches of the same bytes
// resolve to distinct offsets (and therefore distinct line numbers) instead of
// all collapsing onto the first occurrence. Returns -1 when raw is empty or no
// further occurrence exists.
func nextMatchOffset(data, raw []byte, cursor map[string]int) int {
	if len(raw) == 0 {
		return -1
	}
	key := string(raw)
	from := cursor[key]
	if from > len(data) {
		return -1
	}
	idx := bytes.Index(data[from:], raw)
	if idx < 0 {
		return -1
	}
	abs := from + idx
	cursor[key] = abs + 1 // next search starts just past this match
	return abs
}

// rawToFinding converts a raw detector finding to an enriched Finding.
// Generates a deterministic ID and optionally calculates entropy.
// offset is the byte position of this match within chunk.Data (-1 if unknown),
// used to derive the line number.
func (e *Engine) rawToFinding(raw detector.RawFinding, chunk source.Chunk, det detector.Detector, offset int) finding.Finding {
	f := finding.Finding{
		DetectorID:     det.ID(),
		Severity:       det.Severity(),
		Redacted:       raw.Redacted,
		SourceMetadata: chunk.SourceMetadata,
		Verification: finding.VerificationResult{
			Status: finding.StatusUnverified,
		},
		DetectedAt: e.config.Clock(),
		ExtraData:  raw.ExtraData,
	}

	if e.config.ShowRaw {
		f.Raw = string(raw.Raw)
	}

	if e.config.EnableEntropy && len(raw.Raw) > 0 {
		f.Entropy = entropy.Calculate(raw.Raw)
	}

	// Compute the 1-based line number from this match's offset when the source
	// did not already provide one. This powers both human-readable output and
	// inline ignore handling. For multi-line matches (e.g. private keys) this is
	// the line where the match begins.
	if f.SourceMetadata.Line == 0 && offset >= 0 {
		f.SourceMetadata.Line = 1 + bytes.Count(chunk.Data[:offset], []byte{'\n'})
	}

	// Deterministic ID: detectorID + redacted + filePath + line. Including the
	// line disambiguates two findings that share the same redacted value in the
	// same file (e.g. two private keys whose redaction is identical).
	hash := sha256.Sum256([]byte(det.ID() + raw.Redacted + chunk.SourceMetadata.FilePath + strconv.Itoa(f.SourceMetadata.Line)))
	f.ID = fmt.Sprintf("%x", hash[:hashTruncateLen])

	return f
}

// applyFilters applies post-scan filters (severity, verification status).
func (e *Engine) applyFilters(findings []finding.Finding) []finding.Finding {
	var result []finding.Finding
	for _, f := range findings {
		if e.config.OnlyVerified && f.Verification.Status != finding.StatusVerifiedActive {
			continue
		}
		if f.Severity < e.config.MinSeverity {
			continue
		}
		result = append(result, f)
	}
	if result == nil {
		return []finding.Finding{}
	}
	return result
}
