// File: cmd/scan.go

package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/utils"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	scanDir  string
	scanFile string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start a new scan",
	Run: func(cmd *cobra.Command, args []string) {
		apiKey := viper.GetString("api_key")
		apiURL := viper.GetString("api_url")

		if apiKey == "" {
			fmt.Println("API Key is required. Use --api-key flag, set CYBEDEFEND_API_KEY environment variable, or specify in config file.")
			os.Exit(1)
		}

		var zipPath string
		var err error

		if scanDir != "" {
			zipPath, err = utils.ZipDirectory(scanDir)
			if err != nil {
				fmt.Printf("Error zipping directory: %v\n", err)
				os.Exit(1)
			}
		} else if scanFile != "" {
			zipPath = scanFile
		} else {
			fmt.Println("Please provide a directory to scan using --dir or a zip file using --file.")
			cmd.Help()
			os.Exit(1)
		}

		client := api.NewClient(apiURL, apiKey)
		scanID, err := client.StartScan(zipPath)
		if err != nil {
			fmt.Printf("Error starting scan: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Scan started successfully. Scan ID: %s\n", scanID)
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanDir, "dir", "d", "", "Directory to scan")
	scanCmd.Flags().StringVarP(&scanFile, "file", "f", "", "Zip file to scan")
}
