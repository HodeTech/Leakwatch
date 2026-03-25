package cmd

import (
	"runtime"

	"github.com/spf13/cobra"

	gcssource "github.com/cemililik/leakwatch/internal/source/gcs"
)

var scanGCSCmd = &cobra.Command{
	Use:   "gcs <bucket>",
	Short: "Scans a Google Cloud Storage bucket",
	Long: `Scans objects in the specified GCS bucket to detect leaked secrets.
Uses Application Default Credentials for authentication.`,
	Example: `  # Scan an entire GCS bucket
  leakwatch scan gcs my-config-bucket

  # Scan only objects under a specific prefix
  leakwatch scan gcs my-bucket --prefix configs/production/

  # Scan with a specific GCP project
  leakwatch scan gcs my-bucket --project my-gcp-project

  # Output as CSV
  leakwatch scan gcs my-bucket --format csv --output gcs-results.csv`,
	Args: cobra.ExactArgs(1),
	RunE: runScanGCS,
}

func init() {
	scanCmd.AddCommand(scanGCSCmd)

	flags := scanGCSCmd.Flags()
	flags.StringP("format", "f", "json", "output format (json, sarif, csv, table)")
	flags.StringP("output", "o", "", "output file (default: stdout)")
	flags.IntP("concurrency", "c", runtime.NumCPU(), "number of concurrent workers")
	flags.Int64("max-file-size", 10*1024*1024, "maximum file size in bytes")
	flags.Bool("show-raw", false, "show raw secret content in output")
	flags.String("prefix", "", "scan only objects with this key prefix")
	flags.String("project", "", "GCP project ID")

	addVerifyFlags(flags)
	bindScanFlags(flags)
}

func runScanGCS(cmd *cobra.Command, args []string) error {
	cfg, err := loadScanConfig(cmd)
	if err != nil {
		return err
	}

	var opts []gcssource.Option
	opts = append(opts, gcssource.WithMaxFileSize(cfg.maxFileSize))

	if prefix, _ := cmd.Flags().GetString("prefix"); prefix != "" {
		opts = append(opts, gcssource.WithPrefix(prefix))
	}

	if project, _ := cmd.Flags().GetString("project"); project != "" {
		opts = append(opts, gcssource.WithProject(project))
	}

	src := gcssource.New(args[0], opts...)

	return executeScan(cmd.Context(), cfg, src, nil)
}
