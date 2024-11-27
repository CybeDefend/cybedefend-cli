package cmd

import (
	"github.com/spf13/cobra"
)

var helpCmd = &cobra.Command{
	Use:   "help",
	Short: "Show help for cybedefend or a specific command",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			if cmd, _, err := rootCmd.Find(args); err == nil && cmd != nil {
				cmd.Help()
				return
			}
		}
		rootCmd.Help()
	},
}
