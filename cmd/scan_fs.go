package cmd

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/cemililik/leakwatch/internal/source/filesystem"
)

var scanFsCmd = &cobra.Command{
	Use:   "fs <path>",
	Short: "Scans a filesystem directory",
	Long:  `Scans files in the specified directory to detect leaked secrets.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runScanFs,
}

func init() {
	scanCmd.AddCommand(scanFsCmd)

	flags := scanFsCmd.Flags()
	flags.StringP("format", "f", "json", "output format (json)")
	flags.StringP("output", "o", "", "output file (default: stdout)")
	flags.IntP("concurrency", "c", runtime.NumCPU(), "number of concurrent workers")
	flags.Int64("max-file-size", 10*1024*1024, "maximum file size in bytes")
	flags.StringSlice("exclude", nil, "path patterns to exclude")
	flags.Bool("show-raw", false, "show raw secret content in output")

	addVerifyFlags(flags)
	bindScanFlags(flags)
}

func runScanFs(cmd *cobra.Command, args []string) error {
	scanPath := filepath.Clean(args[0])
	absPath, err := filepath.Abs(scanPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	excludePaths, _ := cmd.Flags().GetStringSlice("exclude")

	src := filesystem.New(absPath,
		filesystem.WithMaxFileSize(cfg.maxFileSize),
		filesystem.WithExcludePaths(append(cfg.excludePaths, excludePaths...)),
	)

	return executeScan(cmd.Context(), cfg, src, nil)
}
