package cmd

import (
	"cybedefend-cli/pkg/logger"

	"github.com/spf13/cobra"
)

const Version = "1.0.4"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the version of cybedefend",
	Run: func(cmd *cobra.Command, args []string) {
		logger.Info("CybeDefend CLI version %s", Version)
	},
}
