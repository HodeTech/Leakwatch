// Package cmd defines Leakwatch CLI commands.
// This package is a thin wiring layer; it must not contain business logic.
package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var (
	cfgFile  string
	logLevel string

	buildVersion = "dev"
	buildCommit  = "none"
	buildDate    = "unknown"
)

// SetVersionInfo sets build information (called from main.go).
func SetVersionInfo(version, commit, date string) {
	buildVersion = version
	buildCommit = commit
	buildDate = date
}

// FindingsExitError indicates that secrets were found (exit code 1).
type FindingsExitError struct {
	Count int
}

func (e *FindingsExitError) Error() string {
	return "secrets found"
}

var rootCmd = &cobra.Command{
	Use:   "leakwatch",
	Short: "Detects leaked secrets in codebases",
	Long: `Leakwatch is a high-performance security tool that detects, verifies, and reports
leaked secrets (API keys, passwords, certificates) in codebases, Git histories,
container images, cloud storage buckets, and Slack workspaces.

Features:
  - 64 built-in secret detectors (60 packages) covering AWS, GitHub, Slack, Stripe, JWT, and more
  - 54 verification checks to confirm whether discovered secrets are active
  - Scans filesystems, Git repos, container images, S3, GCS, and Slack
  - Multiple output formats: JSON, SARIF, CSV, and terminal table
  - Aho-Corasick pre-filtering for fast multi-pattern matching
  - Concurrent worker pool architecture for high throughput
  - Custom rules via YAML configuration
  - .leakwatchignore and inline ignore support`,
	Example: `  # Quick scan of current directory
  leakwatch scan fs .

  # Scan a Git repository with verification
  leakwatch scan git https://github.com/org/repo.git

  # Scan and output SARIF for GitHub Code Scanning
  leakwatch scan fs . --format sarif --output results.sarif

  # Scan with remediation guidance
  leakwatch scan fs . --remediation --format table

  # Show only verified active secrets
  leakwatch scan git . --only-verified`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command and returns the exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		var fErr *FindingsExitError
		if errors.As(err, &fErr) {
			return 1
		}
		// Print user-friendly error with suggestion.
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		fmt.Fprintf(os.Stderr, "\nRun 'leakwatch --help' for usage information.\n")
		slog.Debug("command failed", "error", err)
		return 2
	}
	return 0
}

func init() {
	// Config discovery is performed per-command in an isolated Viper instance
	// (see newScanViper in scan_common.go); the global Viper is intentionally not
	// populated here. Binding every scan command's flags to the same global keys
	// caused the last init() to win, so one command's flag defaults masked the
	// active command's flags (SYS-07a/b). Only the logger is initialized globally.
	cobra.OnInitialize(initLogger)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: .leakwatch.yaml)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "warn", "log level (debug, info, warn, error)")
}

func initLogger() {
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		slog.Warn("unknown log level, falling back to warn", "level", logLevel)
		level = slog.LevelWarn
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(handler))
}
