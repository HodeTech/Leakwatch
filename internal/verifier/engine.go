package verifier

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/cemililik/leakwatch/pkg/finding"
)

// DefaultTimeout is the default per-request verification timeout.
const DefaultTimeout = 10 * time.Second

// DefaultConcurrency is the default number of concurrent verification workers.
const DefaultConcurrency = 4

// DefaultRateLimit is the default maximum verification requests per second.
const DefaultRateLimit = 10.0

// Config holds the verification engine configuration.
type Config struct {
	// Enabled controls whether verification is performed at all.
	Enabled bool

	// Timeout is the maximum duration for a single verification request.
	Timeout time.Duration

	// Concurrency is the number of concurrent verification workers.
	Concurrency int

	// RateLimit is the maximum verification requests per second.
	RateLimit float64
}

// DefaultConfig returns a Config with sensible default values.
func DefaultConfig() Config {
	return Config{
		Enabled:     true,
		Timeout:     DefaultTimeout,
		Concurrency: DefaultConcurrency,
		RateLimit:   DefaultRateLimit,
	}
}

// Engine orchestrates concurrent secret verification with rate limiting.
// It maps findings to the appropriate verifier by detector ID and applies
// per-request timeouts and global rate limiting.
type Engine struct {
	verifiers   map[string]Verifier
	rateLimiter *rate.Limiter
	timeout     time.Duration
	concurrency int
	enabled     bool
}

// NewEngine creates a verification engine from the given config and verifier list.
// If cfg.Enabled is false, the engine will pass through findings unmodified.
func NewEngine(cfg Config, vs []Verifier) *Engine {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.RateLimit <= 0 {
		cfg.RateLimit = DefaultRateLimit
	}

	vMap := make(map[string]Verifier, len(vs))
	for _, v := range vs {
		vMap[v.Type()] = v
	}

	burst := int(cfg.RateLimit)
	if burst < 1 {
		burst = 1
	}

	return &Engine{
		verifiers:   vMap,
		rateLimiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), burst),
		timeout:     cfg.Timeout,
		concurrency: cfg.Concurrency,
		enabled:     cfg.Enabled,
	}
}

// VerifyAll verifies all findings concurrently and returns updated findings.
// Findings without a matching verifier are returned with StatusUnverified.
// If the engine is disabled, all findings are returned as-is.
//
// Concurrency safety: each worker writes to a distinct index in the results
// slice. In Go, distinct-index writes to a pre-allocated slice are safe
// without additional synchronization because they target non-overlapping
// memory locations.
func (e *Engine) VerifyAll(ctx context.Context, pairs []VerifyPair) []finding.Finding {
	results := make([]finding.Finding, len(pairs))

	if !e.enabled {
		slog.Debug(
			"verification disabled, skipping all verifications",
			"count", len(pairs),
		)
		for i, p := range pairs {
			results[i] = p.Finding
		}
		return results
	}

	type indexedPair struct {
		index int
		pair  VerifyPair
	}

	// Defensive check: verify no duplicate indices exist in pairs.
	// Each pair maps to a unique index (0..len-1), so this is guaranteed by
	// construction below, but the invariant is critical for concurrent safety.

	// Use a bounded channel buffer to avoid allocating memory proportional to
	// len(pairs). A separate goroutine feeds jobs so workers can start immediately.
	jobs := make(chan indexedPair, e.concurrency)
	var wg sync.WaitGroup

	// Start worker pool.
	workerCount := e.concurrency
	if workerCount > len(pairs) {
		workerCount = len(pairs)
	}
	if workerCount == 0 {
		return results
	}

	wg.Add(workerCount)
	for w := 0; w < workerCount; w++ {
		go func() {
			defer wg.Done()
			for ip := range jobs {
				results[ip.index] = e.verifySingle(ctx, ip.pair)
			}
		}()
	}

	// Feed jobs in a separate goroutine to avoid blocking when buffer is full.
	go func() {
		defer close(jobs)
		for i, p := range pairs {
			jobs <- indexedPair{index: i, pair: p}
		}
	}()

	wg.Wait()
	return results
}

// verifySingle verifies a single finding, applying rate limiting and timeout.
func (e *Engine) verifySingle(ctx context.Context, pair VerifyPair) finding.Finding {
	f := pair.Finding

	v, ok := e.verifiers[pair.Raw.DetectorID]
	if !ok {
		slog.Debug(
			"no verifier registered for detector, skipping",
			"detector_id", pair.Raw.DetectorID,
		)
		return f
	}

	// Apply rate limiting.
	if err := e.rateLimiter.Wait(ctx); err != nil {
		slog.Warn(
			"rate limiter wait cancelled",
			"detector_id", pair.Raw.DetectorID,
			"error", err,
		)
		f.Verification = finding.VerificationResult{
			Status:  finding.StatusVerifyError,
			Message: fmt.Sprintf("rate limiter cancelled: %v", err),
		}
		return f
	}

	// Apply per-request timeout.
	verifyCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	slog.Debug(
		"verifying finding",
		"detector_id", pair.Raw.DetectorID,
		"redacted", pair.Raw.Redacted,
	)

	result := v.Verify(verifyCtx, pair.Raw)
	f.Verification = result

	slog.Debug(
		"verification complete",
		"detector_id", pair.Raw.DetectorID,
		"status", result.Status.String(),
	)

	return f
}
