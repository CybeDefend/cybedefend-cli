// File: cmd/results.go

package cmd

import (
	"cybedefend-cli/pkg/api"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	scanID string
)

var resultsCmd = &cobra.Command{
	Use:   "results",
	Short: "Get scan results",
	Run: func(cmd *cobra.Command, args []string) {
		apiKey := viper.GetString("api_key")
		apiURL := viper.GetString("api_url")

		if apiKey == "" {
			fmt.Println("API Key is required. Use --api-key flag, set CYBEDEFEND_API_KEY environment variable, or specify in config file.")
			os.Exit(1)
		}

		if scanID == "" {
			fmt.Println("Please provide a scan ID using --scan-id.")
			cmd.Help()
			os.Exit(1)
		}

		client := api.NewClient(apiURL, apiKey)
		results, err := client.GetResults(scanID)
		if err != nil {
			fmt.Printf("Error getting results: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Results for Scan ID %s:\n%v\n", scanID, results)
	},
}

func init() {
	resultsCmd.Flags().StringVar(&scanID, "scan-id", "", "Scan ID to retrieve results for")
}
