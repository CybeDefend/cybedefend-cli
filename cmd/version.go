package cmd

import (
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/version"

	"github.com/spf13/cobra"
)

// Version is re-exported for callers that already reference cmd.Version.
// The value itself lives in pkg/version so the SARIF exporter can read it
// without importing this package; bump it there, not here.
const Version = version.Version

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the version of cybedefend",
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("CybeDefend CLI version %s", Version)
	},
}
