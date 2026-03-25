package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/engine"
	gitsource "github.com/cemililik/leakwatch/internal/source/git"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/pkg/finding"
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
	flags.StringP("format", "f", "json", "output format (json, sarif, csv, table)")
	flags.StringP("output", "o", "", "output file (default: stdout)")
	flags.IntP("concurrency", "c", runtime.NumCPU(), "number of concurrent workers per repo")
	flags.Int("parallel", 3, "number of repositories to scan in parallel")
	flags.Int64("max-file-size", 10*1024*1024, "maximum file size in bytes")
	flags.Bool("show-raw", false, "show raw secret content in output")

	addVerifyFlags(flags)
	bindScanFlags(flags)
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

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Collect detectors and configure verifier once.
	detectors := detector.All()
	if len(detectors) == 0 {
		return fmt.Errorf("no registered detectors found")
	}

	verifierCfg := verifier.DefaultConfig()
	if cfg.noVerify {
		verifierCfg.Enabled = false
	}

	// Semaphore to limit parallel repo scans.
	sem := make(chan struct{}, parallel)
	var mu sync.Mutex
	var allFindings []finding.Finding
	var scanErrors []error

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

			slog.Info("scanning repository", "url", url)

			src := gitsource.New(url, gitsource.WithMaxFileSize(cfg.maxFileSize))

			eng := engine.New(engine.Config{
				Concurrency:      cfg.concurrency,
				Detectors:        detectors,
				EnableEntropy:    cfg.enableEntropy,
				EntropyThreshold: cfg.entropyThreshold,
				ShowRaw:          cfg.showRaw,
				VerifierConfig:   verifierCfg,
				Verifiers:        verifier.All(),
				OnlyVerified:     cfg.onlyVerified,
				MinSeverity:      cfg.minSeverity,
			})

			result, err := eng.Scan(ctx, src)

			// Clean up cloned repo.
			if closeErr := src.Close(); closeErr != nil {
				slog.Warn("failed to clean up repo", "url", url, "error", closeErr)
			}

			mu.Lock()
			defer mu.Unlock()

			if err != nil && result == nil {
				scanErrors = append(scanErrors, fmt.Errorf("scan failed for %s: %w", url, err))
				return
			}

			if result != nil {
				allFindings = append(allFindings, result.Findings...)
				slog.Info("repository scan completed", "url", url, "findings", len(result.Findings))
			}
		}(repoURL)
	}

	wg.Wait()

	for _, err := range scanErrors {
		slog.Error("scan error", "error", err)
	}

	// Write output.
	colorEnabled := cfg.format == "table" && cfg.outputFile == ""
	formatter := selectFormatter(cfg.format, cfg.showRaw, colorEnabled)

	var w *os.File
	if cfg.outputFile != "" {
		w, err = os.Create(cfg.outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = w.Close() }()
	} else {
		w = os.Stdout
	}

	// Fallback for nil findings.
	if allFindings == nil {
		allFindings = []finding.Finding{}
	}

	if err := formatter.Format(w, allFindings); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	slog.Info("parallel scan completed", "repos", len(args), "total_findings", len(allFindings))

	if len(allFindings) > 0 {
		return &FindingsExitError{Count: len(allFindings)}
	}

	if len(scanErrors) > 0 {
		return fmt.Errorf("%d repository scans failed", len(scanErrors))
	}

	return nil
}
