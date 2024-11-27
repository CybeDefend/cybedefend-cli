package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

const Version = "1.0.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the version of cybedefend",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("cybedefend version %s\n", Version)
	},
}
