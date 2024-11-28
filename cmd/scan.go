package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/utils"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	scanDir       string
	scanFile      string
	projectIDScan string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start a new scan",
	Run: func(cmd *cobra.Command, args []string) {
		apiKey := viper.GetString("api_key")
		apiURL := viper.GetString("api_url")

		// Retrieve projectIDScan from flag, environment variable, or config
		if projectIDScan == "" {
			projectIDScan = viper.GetString("project_id")
		}

		if apiKey == "" {
			logger.Error("API Key is required. Use --api-key flag, set CYBEDEFEND_API_KEY environment variable, or specify in config file.")
			os.Exit(1)
		}

		if projectIDScan == "" {
			logger.Error("Project ID is required. Use --project-id flag, set CYBEDEFEND_PROJECT_ID environment variable, or specify in config file.")
			os.Exit(1)
		}

		var zipPath string
		var err error

		if scanDir != "" && scanFile != "" {
			logger.Error("Please provide either a directory to scan using --dir or a zip file using --file, not both.")
			os.Exit(1)
		}

		if scanDir != "" {
			logger.Info("Starting scan of directory: %s", scanDir)
			zipPath, err = utils.ZipDirectory(scanDir)
			if err != nil {
				logger.Error("Error zipping directory: %v", err)
				os.Exit(1)
			}
		} else if scanFile != "" {
			logger.Info("Starting scan of a zip file directly: %s", scanFile)
			zipPath = scanFile
		} else {
			logger.Error("Please provide a directory to scan using --dir or a zip file using --file.")
			os.Exit(1)
		}

		client := api.NewClient(apiURL, apiKey)
		scanResult, err := client.StartScan(projectIDScan, zipPath)
		if err != nil {
			logger.Error("Error starting scan: %v", err)
			os.Exit(1)
		}

		if scanDir != "" {
			// Remove the temporary zip file
			err = os.Remove(zipPath)
			if err != nil {
				logger.Error("Error removing temporary zip file: %v", err)
			}
			logger.Debug("Removed temporary zip file: %s", zipPath)
		}

		logger.Success("Scan started successfully. Scan ID: %s", scanResult.ScanID)
		logger.Info("Detected Languages: %v", scanResult.DetectedLanguages)
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanDir, "dir", "d", "", "Directory to scan")
	scanCmd.Flags().StringVarP(&scanFile, "file", "f", "", "Zip file to scan")
	scanCmd.Flags().StringVar(&projectIDScan, "project-id", "", "Project ID")
}
