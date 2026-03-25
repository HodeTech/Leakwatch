package cmd

import "github.com/spf13/cobra"

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Shows Leakwatch version information",
	Example: `  leakwatch version`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Printf("leakwatch %s (commit: %s, built: %s)\n", buildVersion, buildCommit, buildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
