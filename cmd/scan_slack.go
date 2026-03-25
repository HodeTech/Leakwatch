package cmd

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	slacksource "github.com/cemililik/leakwatch/internal/source/slack"
)

var scanSlackCmd = &cobra.Command{
	Use:   "slack",
	Short: "Scans a Slack workspace",
	Long: `Scans messages, channels, and uploaded files in a Slack workspace to detect
leaked secrets such as API keys, passwords, and certificates.

Requires a Slack Bot Token with appropriate scopes (channels:history,
groups:history, im:history, mpim:history, files:read). The token can be
provided via the --token flag or the LEAKWATCH_SLACK_TOKEN environment variable.`,
	Example: `  # Scan all channels using environment variable for token
  export LEAKWATCH_SLACK_TOKEN=xoxb-your-token
  leakwatch scan slack

  # Scan specific channels
  leakwatch scan slack --token xoxb-... --channels general,engineering

  # Scan messages from the last 90 days
  leakwatch scan slack --since 2025-12-25

  # Exclude noisy channels
  leakwatch scan slack --exclude-channels random,social

  # Include direct messages and uploaded files
  leakwatch scan slack --include-dms --include-files

  # Reduce API rate to avoid throttling
  leakwatch scan slack --rate-limit 10`,
	Args: cobra.NoArgs,
	RunE: runScanSlack,
}

func init() {
	scanCmd.AddCommand(scanSlackCmd)

	flags := scanSlackCmd.Flags()
	flags.String("token", "", "Slack Bot Token (or LEAKWATCH_SLACK_TOKEN env var)")
	flags.String("channels", "", "comma-separated channel names to scan (default: all)")
	flags.String("exclude-channels", "", "comma-separated channel names to exclude")
	flags.String("since", "", "scan messages after this date (YYYY-MM-DD)")
	flags.Bool("include-dms", false, "include direct messages")
	flags.Bool("include-files", true, "scan uploaded file content")
	flags.Float64("rate-limit", 20, "max Slack API requests per second")
	flags.StringP("format", "f", "json", "output format (json, sarif, csv, table)")
	flags.StringP("output", "o", "", "output file (default: stdout)")
	flags.IntP("concurrency", "c", runtime.NumCPU(), "number of concurrent workers")
	flags.Int64("max-file-size", 10*1024*1024, "maximum file size in bytes")
	flags.Bool("show-raw", false, "show raw secret content in output")

	addVerifyFlags(flags)
	bindScanFlags(flags)
}

func runScanSlack(cmd *cobra.Command, _ []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	// Resolve token from flag, falling back to environment variable.
	token, _ := cmd.Flags().GetString("token")
	if token == "" {
		token = os.Getenv("LEAKWATCH_SLACK_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("slack bot token is required: use --token or set LEAKWATCH_SLACK_TOKEN")
	}

	var opts []slacksource.Option

	if channels, _ := cmd.Flags().GetString("channels"); channels != "" {
		opts = append(opts, slacksource.WithChannels(splitComma(channels)))
	}

	if excludeChannels, _ := cmd.Flags().GetString("exclude-channels"); excludeChannels != "" {
		opts = append(opts, slacksource.WithExcludeChannels(splitComma(excludeChannels)))
	}

	if sinceStr, _ := cmd.Flags().GetString("since"); sinceStr != "" {
		since, err := time.Parse("2006-01-02", sinceStr)
		if err != nil {
			return fmt.Errorf("invalid --since date format, expected YYYY-MM-DD: %w", err)
		}
		opts = append(opts, slacksource.WithSince(since))
	}

	if includeDMs, _ := cmd.Flags().GetBool("include-dms"); includeDMs {
		opts = append(opts, slacksource.WithIncludeDMs(true))
	}

	if includeFiles, _ := cmd.Flags().GetBool("include-files"); includeFiles {
		opts = append(opts, slacksource.WithIncludeFiles(true))
	}

	if rateLimit, _ := cmd.Flags().GetFloat64("rate-limit"); rateLimit > 0 {
		opts = append(opts, slacksource.WithRateLimit(rateLimit))
	}

	src := slacksource.New(token, opts...)

	return executeScan(cmd.Context(), cfg, src, nil)
}

// splitComma splits a comma-separated string into trimmed, non-empty parts.
func splitComma(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
