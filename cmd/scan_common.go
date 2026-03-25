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
	"github.com/cemililik/leakwatch/internal/filter"
	"github.com/cemililik/leakwatch/internal/output"
	csvout "github.com/cemililik/leakwatch/internal/output/csv"
	jsonout "github.com/cemililik/leakwatch/internal/output/json"
	sarifout "github.com/cemililik/leakwatch/internal/output/sarif"
	tableout "github.com/cemililik/leakwatch/internal/output/table"
	"github.com/cemililik/leakwatch/internal/remediation"
	"github.com/cemililik/leakwatch/internal/source"
	"github.com/cemililik/leakwatch/internal/verifier"
	"github.com/cemililik/leakwatch/pkg/finding"
)

// closeable is implemented by sources that hold resources (e.g. cloned repos).
type closeable interface {
	Close() error
}

// scanConfig holds the resolved configuration for a scan command.
type scanConfig struct {
	concurrency       int
	maxFileSize       int64
	excludePaths      []string
	enableEntropy     bool
	entropyThreshold  float64
	showRaw           bool
	outputFile        string
	format            string
	noVerify          bool
	onlyVerified      bool
	minSeverity       finding.Severity
	enableRemediation bool
	scanRoot          string // root path for .leakwatchignore resolution
}

// bindScanFlags binds common scan flags to Viper.
func bindScanFlags(flags *pflag.FlagSet) {
	if err := viper.BindPFlag("scan.concurrency", flags.Lookup("concurrency")); err != nil {
		slog.Warn("failed to bind concurrency flag", "error", err)
	}
	if err := viper.BindPFlag("scan.max-file-size", flags.Lookup("max-file-size")); err != nil {
		slog.Warn("failed to bind max-file-size flag", "error", err)
	}
	if err := viper.BindPFlag("output.format", flags.Lookup("format")); err != nil {
		slog.Warn("failed to bind format flag", "error", err)
	}
	if err := viper.BindPFlag("output.file", flags.Lookup("output")); err != nil {
		slog.Warn("failed to bind output flag", "error", err)
	}
	if err := viper.BindPFlag("output.show-raw", flags.Lookup("show-raw")); err != nil {
		slog.Warn("failed to bind show-raw flag", "error", err)
	}
}

// addVerifyFlags adds --no-verify, --only-verified and --min-severity flags.
func addVerifyFlags(flags *pflag.FlagSet) {
	flags.Bool("no-verify", false, "disable secret verification")
	flags.Bool("only-verified", false, "only show verified active findings")
	flags.String("min-severity", "low", "minimum severity to report (low, medium, high, critical)")
	flags.Bool("remediation", false, "include remediation guidance in output")
}

// loadScanConfig loads and validates configuration from Viper and flags.
func loadScanConfig(cmd *cobra.Command) (*scanConfig, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	noVerify, err := cmd.Flags().GetBool("no-verify")
	if err != nil {
		slog.Debug("no-verify flag not available", "error", err)
	}
	onlyVerified, err := cmd.Flags().GetBool("only-verified")
	if err != nil {
		slog.Debug("only-verified flag not available", "error", err)
	}
	minSevStr, err := cmd.Flags().GetString("min-severity")
	if err != nil {
		slog.Debug("min-severity flag not available", "error", err)
	}
	minSev := parseSeverity(minSevStr)
	enableRemediation, err := cmd.Flags().GetBool("remediation")
	if err != nil {
		slog.Debug("remediation flag not available", "error", err)
	}

	format, err := cmd.Flags().GetString("format")
	if err != nil || format == "" {
		format = cfg.Output.Format
	}
	outputFile, err := cmd.Flags().GetString("output")
	if err != nil || outputFile == "" {
		outputFile = cfg.Output.File
	}
	showRaw, err := cmd.Flags().GetBool("show-raw")
	if err != nil {
		showRaw = cfg.Output.ShowRaw
	}

	return &scanConfig{
		concurrency:       cfg.Scan.Concurrency,
		maxFileSize:       cfg.Scan.MaxFileSize,
		excludePaths:      cfg.Filter.ExcludePaths,
		enableEntropy:     cfg.Detection.Entropy.Enabled,
		entropyThreshold:  cfg.Detection.Entropy.Threshold,
		showRaw:           showRaw || cfg.Output.ShowRaw,
		outputFile:        outputFile,
		format:            format,
		noVerify:          noVerify,
		onlyVerified:      onlyVerified,
		minSeverity:       minSev,
		enableRemediation: enableRemediation,
	}, nil
}

// selectFormatter returns the appropriate formatter based on the format string.
// When format is "table" and colorEnabled is true, ANSI color codes are used for severity.
func selectFormatter(format string, showRaw bool, colorEnabled bool) output.Formatter {
	switch format {
	case "sarif":
		return &sarifout.Formatter{ShowRaw: showRaw}
	case "csv":
		return &csvout.Formatter{ShowRaw: showRaw}
	case "table":
		return &tableout.Formatter{ShowRaw: showRaw, ColorEnabled: colorEnabled}
	default:
		return &jsonout.Formatter{ShowRaw: showRaw}
	}
}

// executeScan runs the scan pipeline: detect, verify, filter, format, output.
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

	// Warn if --only-verified is used with --no-verify.
	if cfg.onlyVerified && cfg.noVerify {
		slog.Warn("--only-verified has no effect when --no-verify is set")
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
		MinSeverity:      cfg.minSeverity,
	})

	ctx, cancel := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	result, err := eng.Scan(ctx, src)
	if err != nil && result == nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Apply .leakwatchignore if file exists in scan root.
	if cfg.scanRoot != "" {
		ignorePath := filepath.Join(cfg.scanRoot, ".leakwatchignore")
		if rules, err := filter.LoadIgnoreFile(ignorePath); err == nil {
			var filtered []finding.Finding
			for _, f := range result.Findings {
				if !rules.ShouldIgnore(f.SourceMetadata.FilePath) {
					filtered = append(filtered, f)
				}
			}
			result.Findings = filtered
			slog.Debug("applied .leakwatchignore", "path", ignorePath)
		}
	}

	// Enrich findings with remediation guidance if enabled.
	if cfg.enableRemediation {
		result.Findings = remediation.EnrichFindings(result.Findings)
	}

	// Write output.
	// Enable color for table format only when writing to stdout (terminal).
	colorEnabled := cfg.format == "table" && cfg.outputFile == ""
	formatter := selectFormatter(cfg.format, cfg.showRaw, colorEnabled)

	var w io.WriteCloser
	if cfg.outputFile != "" {
		cleanPath := filepath.Clean(cfg.outputFile)
		w, err = os.Create(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = w.Close() }()
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

func parseSeverity(s string) finding.Severity {
	switch s {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	default:
		return finding.SeverityLow
	}
}
