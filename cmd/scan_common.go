package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/HodeTech/leakwatch/internal/config"
	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/internal/detector/custom"
	"github.com/HodeTech/leakwatch/internal/engine"
	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/output"
	csvout "github.com/HodeTech/leakwatch/internal/output/csv"
	jsonout "github.com/HodeTech/leakwatch/internal/output/json"
	sarifout "github.com/HodeTech/leakwatch/internal/output/sarif"
	tableout "github.com/HodeTech/leakwatch/internal/output/table"
	"github.com/HodeTech/leakwatch/internal/remediation"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/internal/verifier"
	"github.com/HodeTech/leakwatch/pkg/finding"
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
	excludeDetectors  []string
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
	scanTarget        string // display name for scan summary (path, URL, image ref)

	// Verification engine settings sourced from the `verification:` config block.
	verifyEnabled     bool
	verifyTimeout     time.Duration
	verifyConcurrency int
	verifyRateLimit   float64

	// User-defined YAML custom rules from the `custom-rules:` config block.
	customRules []custom.RuleDef
}

// Flag names shared across the scan_*.go commands. Defining them as constants
// avoids duplicating the string literals that several commands reference when
// registering and reading the same flag.
const flagShowRaw = "show-raw"

// scanFlagBindings maps Viper config keys to the scan flag that overrides them.
// Each scan command's pflags are bound to a fresh, per-invocation Viper instance
// (see newScanViper) so that one command's flag defaults never leak into another
// command's resolved config. Binding a flag only takes effect when the user
// explicitly sets it; otherwise Viper falls back to env vars, the config file,
// and finally the registered defaults — preserving flag > env > file > default
// precedence. A flag that does not exist on a given command is skipped.
var scanFlagBindings = map[string]string{
	"scan.concurrency":   "concurrency",
	"scan.max-file-size": "max-file-size",
	"output.format":      "format",
	"output.file":        "output",
	"output.show-raw":    flagShowRaw,
}

// bindScanFlags binds the current command's common scan flags to the given,
// per-invocation Viper instance. Only flags present on the command are bound.
func bindScanFlags(v *viper.Viper, flags *pflag.FlagSet) {
	for key, flagName := range scanFlagBindings {
		f := flags.Lookup(flagName)
		if f == nil {
			continue
		}
		if err := v.BindPFlag(key, f); err != nil {
			slog.Warn("failed to bind scan flag", "flag", flagName, "error", err)
		}
	}
}

// newScanViper builds an isolated Viper instance for a single scan invocation.
// It replicates the global config discovery performed in cmd/root.go's
// initConfig (respecting --config, otherwise searching the working directory
// and home directory for .leakwatch.yaml), enables LEAKWATCH_-prefixed env var
// overrides with the same key replacer, and binds the active command's pflags so
// that flag > env > config-file > default precedence holds without cross-command
// global-state leakage (SYS-07a/b).
func newScanViper(cmd *cobra.Command) *viper.Viper {
	v := viper.New()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName(".leakwatch")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(home)
		}
	}

	v.SetEnvPrefix("LEAKWATCH")
	// Map nested config keys to env vars: scan.concurrency -> LEAKWATCH_SCAN_CONCURRENCY,
	// output.severity-threshold -> LEAKWATCH_OUTPUT_SEVERITY_THRESHOLD.
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		// A missing config file is acceptable; only surface genuine parse errors.
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) && v.ConfigFileUsed() != "" {
			slog.Warn("failed to parse config file", "file", v.ConfigFileUsed(), "error", err)
		}
	}

	bindScanFlags(v, cmd.Flags())
	return v
}

// addVerifyFlags adds --no-verify, --only-verified and --min-severity flags.
func addVerifyFlags(flags *pflag.FlagSet) {
	flags.Bool("no-verify", false, "disable secret verification")
	flags.Bool("only-verified", false, "only show verified active findings")
	flags.String("min-severity", "low", "minimum severity to report (low, medium, high, critical)")
	flags.Bool("remediation", false, "include remediation guidance in output")
}

// loadScanConfig loads and validates configuration for the active command using
// an isolated Viper instance whose only bound flags are this command's own. This
// guarantees that flags such as --concurrency, --max-file-size, and --format
// honor flag > env > config-file > default precedence without picking up another
// scan command's flag defaults (SYS-07a/b). Flags that are not config-keyed
// (--no-verify, --only-verified, --min-severity, --remediation, --exclude) are
// read directly from the command.
func loadScanConfig(cmd *cobra.Command) (*scanConfig, error) {
	v := newScanViper(cmd)
	cfg, err := config.LoadFrom(v)
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
	// The --min-severity flag takes precedence; fall back to the
	// output.severity-threshold config value only when the flag is not set.
	if !cmd.Flags().Changed("min-severity") && cfg.Output.SeverityThreshold != "" {
		minSevStr = cfg.Output.SeverityThreshold
	}
	minSev := parseSeverity(minSevStr)
	enableRemediation, err := cmd.Flags().GetBool("remediation")
	if err != nil {
		slog.Debug("remediation flag not available", "error", err)
	}

	// show-raw is bound to the isolated Viper, so cfg.Output.ShowRaw already
	// reflects flag > env > config > default. The explicit-set check lets
	// --show-raw=false override a config `show-raw: true` (OUT-m-04).
	showRaw := cfg.Output.ShowRaw
	if cmd.Flags().Changed(flagShowRaw) {
		showRaw, _ = cmd.Flags().GetBool(flagShowRaw)
	}

	return &scanConfig{
		concurrency:       cfg.Scan.Concurrency,
		maxFileSize:       cfg.Scan.MaxFileSize,
		excludePaths:      cfg.Filter.ExcludePaths,
		excludeDetectors:  cfg.Filter.ExcludeDetectors,
		enableEntropy:     cfg.Detection.Entropy.Enabled,
		entropyThreshold:  cfg.Detection.Entropy.Threshold,
		showRaw:           showRaw,
		outputFile:        cfg.Output.File,
		format:            cfg.Output.Format,
		noVerify:          noVerify,
		onlyVerified:      onlyVerified,
		minSeverity:       minSev,
		enableRemediation: enableRemediation,
		verifyEnabled:     cfg.Verification.Enabled,
		verifyTimeout:     cfg.Verification.Timeout,
		verifyConcurrency: cfg.Verification.Concurrency,
		verifyRateLimit:   cfg.Verification.RateLimit,
		customRules:       cfg.CustomRules,
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

// resolveColorEnabled decides whether ANSI color should be used for the given
// format/output destination by inspecting the real process environment: stdout
// must be a character device (a terminal, not a pipe/redirect) and the NO_COLOR
// convention (https://no-color.org) must not be set. It delegates the pure
// decision to shouldEnableColor so the policy can be unit-tested without a TTY.
func resolveColorEnabled(format, outputFile string) bool {
	_, noColor := os.LookupEnv("NO_COLOR")
	return shouldEnableColor(format, outputFile, stdoutIsTerminal(), noColor)
}

// shouldEnableColor is the pure color-policy decision: color is enabled only for
// table output written to stdout, when stdout is a terminal and NO_COLOR is unset.
func shouldEnableColor(format, outputFile string, stdoutIsTTY, noColor bool) bool {
	if format != "table" || outputFile != "" {
		return false
	}
	if noColor {
		return false
	}
	return stdoutIsTTY
}

// stdoutIsTerminal reports whether os.Stdout is connected to a terminal rather
// than a pipe or redirected file. It uses the ModeCharDevice bit from Stat so no
// extra dependency is required; pipes and regular files lack this bit, so ANSI
// escape sequences never leak into captured or redirected output (OUT-M-03).
func stdoutIsTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
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

	engCfg, err := buildEngineConfig(cfg)
	if err != nil {
		return err
	}
	eng := engine.New(engCfg)

	ctx, cancel := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	result, err := eng.Scan(ctx, src)
	if err != nil && result == nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	return renderResult(cfg, result, src.Type(), cfg.scanRoot)
}

// renderResult finishes the shared scan pipeline for an already-produced
// ScanResult: it applies .leakwatchignore (searched in ignoreRoot, then CWD),
// enriches findings with remediation guidance when enabled, writes the formatted
// output to the configured destination, prints the scan summary to stderr, and
// returns a FindingsExitError when any findings remain. Both single-source scans
// (executeScan) and the multi-repo scan (runScanRepos) funnel through here so
// their output behavior cannot drift (CMD-M-04).
func renderResult(cfg *scanConfig, result *engine.ScanResult, sourceType, ignoreRoot string) error {
	result.Findings = applyLeakwatchIgnore(result.Findings, ignoreRoot)

	if cfg.enableRemediation {
		result.Findings = remediation.EnrichFindings(result.Findings)
	}
	if result.Findings == nil {
		result.Findings = []finding.Finding{}
	}

	colorEnabled := resolveColorEnabled(cfg.format, cfg.outputFile)
	formatter := selectFormatter(cfg.format, cfg.showRaw, colorEnabled)

	var w io.WriteCloser
	if cfg.outputFile != "" {
		cleanPath := filepath.Clean(cfg.outputFile)
		f, err := os.Create(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() { _ = f.Close() }()
		w = f
	} else {
		w = os.Stdout
	}

	if err := formatter.Format(w, result.Findings); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	// Print scan summary to stderr (visible regardless of output format/file).
	printScanSummary(result, sourceType, cfg.scanTarget)

	if len(result.Findings) > 0 {
		return &FindingsExitError{Count: len(result.Findings)}
	}

	return nil
}

// printScanSummary writes scan metadata to stderr.
func printScanSummary(result *engine.ScanResult, sourceType string, target string) {
	fmt.Fprintf(os.Stderr, "\n── Scan Summary ─────────────────────────────────\n")
	fmt.Fprintf(os.Stderr, "  Date:            %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(os.Stderr, "  Source:          %s\n", sourceType)
	if target != "" {
		fmt.Fprintf(os.Stderr, "  Target:          %s\n", target)
	}
	fmt.Fprintf(os.Stderr, "  Files scanned:   %d\n", result.ScannedChunks)
	fmt.Fprintf(os.Stderr, "  Duration:        %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "  Findings:        %d\n", len(result.Findings))
	if result.Interrupted {
		fmt.Fprintf(os.Stderr, "  Status:          interrupted (partial results)\n")
	}
	fmt.Fprintf(os.Stderr, "─────────────────────────────────────────────────\n\n")
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

// buildEngineConfig registers custom rules, applies detector exclusions, and
// assembles the engine.Config shared by every scan command (fs/git/image/s3/
// gcs/slack and repos). Centralizing this guarantees that custom-rules,
// verification.*, and exclude-detectors take effect uniformly — previously
// `scan repos` built its own config and silently ignored all three.
func buildEngineConfig(cfg *scanConfig) (engine.Config, error) {
	// Register user-defined custom rules (from the `custom-rules:` config block)
	// before snapshotting the detector set so they participate in the scan.
	if len(cfg.customRules) > 0 {
		count, errs := custom.RegisterCustomRules(cfg.customRules)
		for _, e := range errs {
			slog.Warn("custom rule registration skipped", "error", e)
		}
		slog.Info("custom rules registered", "count", count, "skipped", len(errs))
	}

	detectors := detector.All()
	if len(cfg.excludeDetectors) > 0 {
		detectors = excludeDetectorsByID(detectors, cfg.excludeDetectors)
	}
	if len(detectors) == 0 {
		return engine.Config{}, fmt.Errorf("no registered detectors found")
	}
	slog.Debug("detectors loaded", "count", len(detectors))

	// Configure verification from the `verification:` config block.
	// The --no-verify CLI flag takes precedence over the config value.
	verifierCfg := verifier.Config{
		Enabled:     cfg.verifyEnabled,
		Timeout:     cfg.verifyTimeout,
		Concurrency: cfg.verifyConcurrency,
		RateLimit:   cfg.verifyRateLimit,
	}
	if cfg.noVerify {
		verifierCfg.Enabled = false
	}
	if cfg.onlyVerified && cfg.noVerify {
		slog.Warn("--only-verified has no effect when --no-verify is set")
	}

	return engine.Config{
		Concurrency:      cfg.concurrency,
		Detectors:        detectors,
		EnableEntropy:    cfg.enableEntropy,
		EntropyThreshold: cfg.entropyThreshold,
		ShowRaw:          cfg.showRaw,
		VerifierConfig:   verifierCfg,
		Verifiers:        verifier.All(),
		OnlyVerified:     cfg.onlyVerified,
		MinSeverity:      cfg.minSeverity,
	}, nil
}

// applyLeakwatchIgnore filters findings through the first .leakwatchignore found
// in scanRoot, then the current working directory. scanRoot may be empty.
func applyLeakwatchIgnore(findings []finding.Finding, scanRoot string) []finding.Finding {
	var ignoreRules *filter.IgnoreRules
	for _, dir := range []string{scanRoot, "."} {
		if dir == "" {
			continue
		}
		ignorePath := filepath.Join(dir, ".leakwatchignore")
		if rules, err := filter.LoadIgnoreFile(ignorePath); err == nil {
			ignoreRules = rules
			slog.Debug("loaded .leakwatchignore", "path", ignorePath)
			break
		}
	}
	if ignoreRules == nil {
		return findings
	}
	filtered := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if !ignoreRules.ShouldIgnore(f.SourceMetadata.FilePath) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// excludeDetectorsByID returns the detectors whose ID is not in the exclude list.
func excludeDetectorsByID(detectors []detector.Detector, exclude []string) []detector.Detector {
	excluded := make(map[string]bool, len(exclude))
	for _, id := range exclude {
		excluded[id] = true
	}
	kept := make([]detector.Detector, 0, len(detectors))
	for _, d := range detectors {
		if excluded[d.ID()] {
			slog.Debug("detector excluded by config", "detector_id", d.ID())
			continue
		}
		kept = append(kept, d)
	}
	return kept
}
