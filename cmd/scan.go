package cmd

import "github.com/spf13/cobra"

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Starts a secret scan",
	Long: `Sub-commands for scanning various targets for leaked secrets.
Supports filesystem directories, Git repositories, container images,
AWS S3 buckets, Google Cloud Storage buckets, Slack workspaces,
and parallel multi-repo scanning.`,
	Example: `  # Scan a local directory
  leakwatch scan fs /path/to/project

  # Scan a Git repository
  leakwatch scan git https://github.com/org/repo.git

  # Scan a container image
  leakwatch scan image myapp:latest

  # Scan an S3 bucket
  leakwatch scan s3 my-bucket

  # Scan a GCS bucket
  leakwatch scan gcs my-bucket

  # Scan a Slack workspace
  leakwatch scan slack --token xoxb-...

  # Scan multiple repos in parallel
  leakwatch scan repos https://github.com/org/repo1.git https://github.com/org/repo2.git`,
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
