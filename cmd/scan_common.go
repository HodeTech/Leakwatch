package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/cemililik/leakwatch/internal/config"
	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/engine"
	jsonout "github.com/cemililik/leakwatch/internal/output/json"
	"github.com/cemililik/leakwatch/internal/source"
	"github.com/cemililik/leakwatch/internal/verifier"
)

// closeable is implemented by sources that hold resources (e.g. cloned repos).
type closeable interface {
	Close() error
}

// scanConfig holds the resolved configuration for a scan command.
type scanConfig struct {
	concurrency      int
	maxFileSize      int64
	excludePaths     []string
	enableEntropy    bool
	entropyThreshold float64
	showRaw          bool
	outputFile       string
	format           string
	noVerify         bool
	onlyVerified     bool
}

// bindScanFlags binds common scan flags to Viper.
func bindScanFlags(flags *pflag.FlagSet) {
	_ = viper.BindPFlag("scan.concurrency", flags.Lookup("concurrency"))
	_ = viper.BindPFlag("scan.max-file-size", flags.Lookup("max-file-size"))
	_ = viper.BindPFlag("output.format", flags.Lookup("format"))
	_ = viper.BindPFlag("output.file", flags.Lookup("output"))
	_ = viper.BindPFlag("output.show-raw", flags.Lookup("show-raw"))
}

// addVerifyFlags adds --no-verify and --only-verified flags to a command.
func addVerifyFlags(flags *pflag.FlagSet) {
	flags.Bool("no-verify", false, "disable secret verification")
	flags.Bool("only-verified", false, "only show verified active findings")
}

// loadScanConfig loads and validates configuration from Viper.
func loadScanConfig(cmd *cobra.Command) (*scanConfig, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	noVerify, _ := cmd.Flags().GetBool("no-verify")
	onlyVerified, _ := cmd.Flags().GetBool("only-verified")

	return &scanConfig{
		concurrency:      cfg.Scan.Concurrency,
		maxFileSize:      cfg.Scan.MaxFileSize,
		excludePaths:     cfg.Filter.ExcludePaths,
		enableEntropy:    cfg.Detection.Entropy.Enabled,
		entropyThreshold: cfg.Detection.Entropy.Threshold,
		showRaw:          cfg.Output.ShowRaw,
		outputFile:       cfg.Output.File,
		format:           cfg.Output.Format,
		noVerify:         noVerify,
		onlyVerified:     onlyVerified,
	}, nil
}

// executeScan runs the scan pipeline: detect, verify, format, output.
// If cl is non-nil, Close() is called when the scan completes.
func executeScan(parent context.Context, cfg *scanConfig, src source.Source, cl closeable) error {
	if cl != nil {
		defer func() {
			if err := cl.Close(); err != nil {
				slog.Warn("failed to clean up source", "error", err)
			}
		}()
	}

	detectors := detector.All()
	if len(detectors) == 0 {
		return fmt.Errorf("no registered detectors found")
	}
	slog.Debug("detectors loaded", "count", len(detectors))

	// Configure verification.
	verifierCfg := verifier.DefaultConfig()
	if cfg.noVerify {
		verifierCfg.Enabled = false
	}

	eng := engine.New(engine.Config{
		Concurrency:      cfg.concurrency,
		Detectors:        detectors,
		EnableEntropy:    cfg.enableEntropy,
		EntropyThreshold: cfg.entropyThreshold,
		ShowRaw:          cfg.showRaw,
		VerifierConfig:   verifierCfg,
		Verifiers:        verifier.All(),
		OnlyVerified:     cfg.onlyVerified,
	})

	ctx, cancel := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	result, err := eng.Scan(ctx, src)
	if err != nil && result == nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Write output.
	formatter := &jsonout.Formatter{ShowRaw: cfg.showRaw}

	var w io.WriteCloser
	if cfg.outputFile != "" {
		cleanPath := filepath.Clean(cfg.outputFile)
		w, err = os.Create(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer w.Close()
	} else {
		w = os.Stdout
	}

	if err := formatter.Format(w, result.Findings); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	if len(result.Findings) > 0 {
		slog.Info("secrets found", "count", len(result.Findings))
		return &FindingsExitError{Count: len(result.Findings)}
	}

	return nil
}
