package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/utils"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	projectIDResults string
	resultType       string // "sast" or "iac"
	page             int    // page number
	outputFormat     string // "json" or "html"
	outputFile       string // file name
	outputPath       string // file path
)

var resultsCmd = &cobra.Command{
	Use:   "results",
	Short: "Get scan results",
	Run: func(cmd *cobra.Command, args []string) {
		apiKey := viper.GetString("api_key")
		apiURL := viper.GetString("api_url")

		if projectIDResults == "" {
			projectIDResults = viper.GetString("project_id")
		}

		if apiKey == "" {
			logger.Error("API Key is required. Use --api-key flag, set CYBEDEFEND_API_KEY environment variable, or specify in config file.")
			os.Exit(1)
		}

		if projectIDResults == "" {
			logger.Error("Project ID is required. Use --project-id flag, set CYBEDEFEND_PROJECT_ID environment variable, or specify in config file.")
			os.Exit(1)
		}

		if outputFormat != "json" && outputFormat != "html" {
			logger.Error("Invalid output format: %s. Use 'json' or 'html'.", outputFormat)
			os.Exit(1)
		}

		if page < 1 {
			logger.Error("Invalid page number: %d. Must be greater than 0.", page)
			os.Exit(1)
		}

		if outputFormat == "html" && outputFile == "results.json" {
			outputFile = "results.html"
		}

		if outputFormat == "html" && filepath.Ext(outputFile) != ".html" {
			logger.Error("Invalid output file extension: %s. Must be .html for HTML output.", filepath.Ext(outputFile))
			os.Exit(1)
		}

		if outputFormat == "json" && filepath.Ext(outputFile) != ".json" {
			logger.Error("Invalid output file extension: %s. Must be .json for JSON output.", filepath.Ext(outputFile))
			os.Exit(1)
		}

		if resultType != "sast" && resultType != "iac" {
			logger.Error("Invalid result type: %s. Use 'sast' or 'iac'.", resultType)
			os.Exit(1)
		}

		logger.Info("Fetching results for project %s, type %s, page %d", projectIDResults, resultType, page)

		// Create the client
		client := api.NewClient(apiURL, apiKey)

		// Fetch results
		results, err := client.GetResults(projectIDResults, resultType, page)
		if err != nil {
			logger.Error("Error fetching results: %v", err)
			os.Exit(1)
		}

		// Check if the page is valid
		if page > results.TotalPages {
			logger.Warn("Requested page %d exceeds total pages (%d). Fetching last page instead.", page, results.TotalPages)
			results, err = client.GetResults(projectIDResults, resultType, results.TotalPages)
			if err != nil {
				logger.Error("Error fetching last page: %v", err)
				os.Exit(1)
			}
		}

		// Determine output path
		outputFilePath := filepath.Join(outputPath, outputFile)

		// Handle output format
		switch outputFormat {
		case "json":
			writeJSONOutput(results, outputFilePath)
		case "html":
			writeHTMLOutput(results, outputFilePath)
		default:
			logger.Error("Invalid output format: %s. Use 'json' or 'html'.", outputFormat)
			os.Exit(1)
		}

		logger.Success("Results saved successfully to %s", outputFilePath)
	},
}

func init() {
	resultsCmd.Flags().StringVar(&projectIDResults, "project-id", "", "Project ID")
	resultsCmd.Flags().StringVarP(&resultType, "type", "t", "sast", "Result type (sast or iac)")
	resultsCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to fetch")
	resultsCmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format (json or html)")
	resultsCmd.Flags().StringVarP(&outputFile, "filename", "f", "results.json", "Output file name")
	resultsCmd.Flags().StringVar(&outputPath, "filepath", ".", "Output file path")
}

// writeJSONOutput writes results as JSON to the specified file
func writeJSONOutput(results interface{}, filePath string) {
	file, err := os.Create(filePath)
	if err != nil {
		logger.Error("Error creating file: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		logger.Error("Error writing JSON to file: %v", err)
		os.Exit(1)
	}
}

// writeHTMLOutput writes results as HTML to the specified file
func writeHTMLOutput(results *api.ScanResults, filePath string) {
	// Map api.ScanResults to utils.VulnerabilityReport
	report := &utils.VulnerabilityReport{
		ProjectName:       results.ProjectName,
		ProjectID:         results.ProjectID,
		Total:             results.Total,
		Page:              results.Page,
		TotalPages:        results.TotalPages,
		Severity:          results.Severity,
		Vulnerabilities:   mapVulnerabilities(results.Vulnerabilities),
		VulnerabilityType: resultType,
	}

	// Generate the HTML report
	err := utils.RenderHTMLReport(*report, filePath)
	if err != nil {
		logger.Error("Error generating HTML report: %v", err)
		os.Exit(1)
	}

}

// mapVulnerabilities converts []api.Vulnerability to []utils.Vulnerability
func mapVulnerabilities(apiVulns []api.Vulnerability) []utils.Vulnerability {
	var utilsVulns []utils.Vulnerability
	for _, v := range apiVulns {
		utilsVulns = append(utilsVulns, utils.Vulnerability{
			ID:                  v.ID,
			Name:                v.Details.Name,
			Description:         v.Details.Description,
			Severity:            v.Details.Severity,
			Language:            v.Language,
			Path:                v.Path,
			VulnerableStartLine: v.VulnerableStartLine,
			VulnerableEndLine:   v.VulnerableEndLine,
			HowToPrevent:        v.Details.HowToPrevent,
			CWE:                 v.Details.CWE,
			OWASP:               v.Details.OWASP,
		})
	}
	return utilsVulns
}
