package cmd

import (
	"fmt"
	"log/slog"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/HodeTech/leakwatch/internal/engine"
	gitsource "github.com/HodeTech/leakwatch/internal/source/git"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var scanReposCmd = &cobra.Command{
	Use:   "repos <url1> <url2> [url...]",
	Short: "Scans multiple Git repositories in parallel",
	Long: `Scans multiple Git repositories concurrently. Each repository is cloned
and scanned independently. Results are combined into a single output.`,
	Example: `  # Scan two repositories
  leakwatch scan repos https://github.com/org/repo1.git https://github.com/org/repo2.git

  # Scan multiple repos with higher parallelism
  leakwatch scan repos --parallel 5 \
    https://github.com/org/api.git \
    https://github.com/org/web.git \
    https://github.com/org/infra.git

  # Output combined results as table
  leakwatch scan repos --format table \
    https://github.com/org/repo1.git \
    https://github.com/org/repo2.git`,
	Args: cobra.MinimumNArgs(2),
	RunE: runScanRepos,
}

func init() {
	scanCmd.AddCommand(scanReposCmd)

	flags := scanReposCmd.Flags()
	flags.StringP("format", "f", "json", "output format (json, sarif, csv, table, github)")
	flags.StringP("output", "o", "", "output file (default: stdout)")
	flags.IntP("concurrency", "c", runtime.NumCPU(), "number of concurrent workers per repo")
	flags.Int("parallel", 3, "number of repositories to scan in parallel")
	flags.Int64("max-file-size", 10*1024*1024, "maximum file size in bytes")
	flags.Bool(flagShowRaw, false, "show raw secret content in output")

	addVerifyFlags(flags)
}

func runScanRepos(cmd *cobra.Command, args []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	parallel, err := cmd.Flags().GetInt("parallel")
	if err != nil || parallel < 1 {
		parallel = 3
	}

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Build the shared engine config once (registers custom-rules, applies
	// exclude-detectors, and wires verification.* from config). The same
	// immutable config is reused for every repo's engine.
	engCfg, err := buildEngineConfig(cfg)
	if err != nil {
		return err
	}

	// Reuse the same source options (max file size, exclude-paths) for every repo.
	srcOpts := []gitsource.Option{gitsource.WithMaxFileSize(cfg.maxFileSize)}
	if len(cfg.excludePaths) > 0 {
		srcOpts = append(srcOpts, gitsource.WithExcludePaths(cfg.excludePaths))
	}

	scanStart := time.Now()

	// Semaphore to limit parallel repo scans.
	sem := make(chan struct{}, parallel)
	var mu sync.Mutex
	var allFindings []finding.Finding
	var scanErrors []error
	var totalChunks int

	var wg sync.WaitGroup
	for _, repoURL := range args {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			select {
			case <-ctx.Done():
				return
			default:
			}

			// displayURL strips any embedded credentials so a URL like
			// https://user:TOKEN@host/repo.git never leaks to logs, errors, or
			// output. The real url is still passed to gitsource.New for cloning.
			displayURL := gitsource.SafeDisplayURL(url)

			slog.Info("scanning repository", "url", displayURL)

			src := gitsource.New(url, srcOpts...)

			eng := engine.New(engCfg)

			result, err := eng.Scan(ctx, src)

			// Clean up cloned repo.
			if closeErr := src.Close(); closeErr != nil {
				slog.Warn("failed to clean up repo", "url", displayURL, "error", closeErr)
			}

			mu.Lock()
			defer mu.Unlock()

			if err != nil && result == nil {
				scanErrors = append(scanErrors, fmt.Errorf("scan failed for %s: %w", displayURL, err))
				return
			}

			if result != nil {
				allFindings = append(allFindings, result.Findings...)
				totalChunks += result.ScannedChunks
				slog.Info("repository scan completed", "url", displayURL, "findings", len(result.Findings), "files", result.ScannedChunks)
			}
		}(repoURL)
	}

	wg.Wait()

	for _, err := range scanErrors {
		slog.Error("scan error", "error", err)
	}

	// Funnel the combined result through the shared render pipeline so
	// .leakwatchignore, remediation, formatting, output, and the summary behave
	// identically to single-source scans (CMD-M-04). The ignore root is empty so
	// only a CWD .leakwatchignore applies (repos are remote/temporary clones).
	cfg.scanTarget = fmt.Sprintf("%d repositories", len(args))
	combined := &engine.ScanResult{
		Findings:      allFindings,
		ScannedChunks: totalChunks,
		Duration:      time.Since(scanStart),
		Interrupted:   ctx.Err() != nil,
	}

	renderErr := renderResult(cfg, combined, "repos", "")

	// A failed scan must surface even when no findings were produced; only report
	// it when the render pipeline itself did not already return a findings exit.
	if renderErr == nil && len(scanErrors) > 0 {
		return fmt.Errorf("%d repository scans failed", len(scanErrors))
	}

	return renderErr
}
