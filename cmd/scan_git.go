package cmd

import (
	"fmt"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	gitsource "github.com/cemililik/leakwatch/internal/source/git"
)

var scanGitCmd = &cobra.Command{
	Use:   "git <url_or_path>",
	Short: "Scans a Git repository",
	Long: `Scans the entire commit history of the specified Git repository to detect
leaked secrets. Both local and remote (HTTP/SSH) repositories are supported.`,
	Args: cobra.ExactArgs(1),
	RunE: runScanGit,
}

func init() {
	scanCmd.AddCommand(scanGitCmd)

	flags := scanGitCmd.Flags()
	flags.StringP("format", "f", "json", "output format (json)")
	flags.StringP("output", "o", "", "output file (default: stdout)")
	flags.IntP("concurrency", "c", runtime.NumCPU(), "number of concurrent workers")
	flags.Int64("max-file-size", 10*1024*1024, "maximum file size in bytes")
	flags.Bool("show-raw", false, "show raw secret content in output")
	flags.String("since", "", "scan commits after this date (YYYY-MM-DD)")
	flags.String("since-commit", "", "scan changes from this commit to HEAD")
	flags.String("branch", "", "branch to scan")
	flags.Int("depth", 0, "clone depth (remote repos only, 0=all)")

	addVerifyFlags(flags)
	bindScanFlags(flags)
}

func runScanGit(cmd *cobra.Command, args []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	var opts []gitsource.Option
	opts = append(opts, gitsource.WithMaxFileSize(cfg.maxFileSize))

	if since, _ := cmd.Flags().GetString("since"); since != "" {
		t, err := time.Parse("2006-01-02", since)
		if err != nil {
			return fmt.Errorf("invalid date format (expected YYYY-MM-DD): %w", err)
		}
		opts = append(opts, gitsource.WithSince(t))
	}

	if sinceCommit, _ := cmd.Flags().GetString("since-commit"); sinceCommit != "" {
		opts = append(opts, gitsource.WithSinceCommit(sinceCommit))
	}

	if branch, _ := cmd.Flags().GetString("branch"); branch != "" {
		opts = append(opts, gitsource.WithBranch(branch))
	}

	if depth, _ := cmd.Flags().GetInt("depth"); depth > 0 {
		opts = append(opts, gitsource.WithDepth(depth))
	}

	src := gitsource.New(args[0], opts...)

	return executeScan(cmd.Context(), cfg, src, src)
}
