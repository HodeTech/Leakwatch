package cmd

import (
	"runtime"

	"github.com/spf13/cobra"

	s3source "github.com/HodeTech/leakwatch/internal/source/s3"
)

var scanS3Cmd = &cobra.Command{
	Use:   "s3 <bucket>",
	Short: "Scans an AWS S3 bucket",
	Long: `Scans objects in the specified AWS S3 bucket to detect leaked secrets.
Uses the default AWS credential chain (env vars, shared config, IAM role).`,
	Example: `  # Scan an entire S3 bucket
  leakwatch scan s3 my-config-bucket

  # Scan only objects under a specific prefix
  leakwatch scan s3 my-bucket --prefix configs/

  # Scan a bucket in a specific region
  leakwatch scan s3 my-bucket --region eu-west-1

  # Output as SARIF
  leakwatch scan s3 my-bucket --format sarif --output s3-results.sarif`,
	Args: cobra.ExactArgs(1),
	RunE: runScanS3,
}

func init() {
	scanCmd.AddCommand(scanS3Cmd)

	flags := scanS3Cmd.Flags()
	flags.StringP("format", "f", "json", "output format (json, sarif, csv, table, github)")
	flags.StringP("output", "o", "", "output file (default: stdout)")
	flags.IntP("concurrency", "c", runtime.NumCPU(), "number of concurrent workers")
	flags.Int64("max-file-size", 10*1024*1024, "maximum file size in bytes")
	flags.Bool(flagShowRaw, false, "show raw secret content in output")
	flags.String("prefix", "", "scan only objects with this key prefix")
	flags.String("region", "", "AWS region (default: from AWS config)")

	addVerifyFlags(flags)
}

func runScanS3(cmd *cobra.Command, args []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	var opts []s3source.Option
	opts = append(opts, s3source.WithMaxFileSize(cfg.maxFileSize))

	if len(cfg.excludePaths) > 0 {
		opts = append(opts, s3source.WithExcludePaths(cfg.excludePaths))
	}

	if prefix, _ := cmd.Flags().GetString("prefix"); prefix != "" {
		opts = append(opts, s3source.WithPrefix(prefix))
	}

	if region, _ := cmd.Flags().GetString("region"); region != "" {
		opts = append(opts, s3source.WithRegion(region))
	}

	cfg.scanTarget = "s3://" + args[0]
	src := s3source.New(args[0], opts...)

	return executeScan(cmd.Context(), cfg, src, nil)
}
