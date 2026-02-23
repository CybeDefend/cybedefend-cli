package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/utils"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	projectIDResults string
	resultType       string // "sast" or "iac"
	page             int    // page number
	outputFormat     string // "json", "html", or "sarif"
	outputFile       string // file name
	outputPath       string // file path
	allResults       bool   // fetch all results
)

var resultsCmd = &cobra.Command{
	Use:   "results",
	Short: "Get scan results",
	Run:   executeResultsCommand,
}

func init() {
	resultsCmd.Flags().StringVar(&projectIDResults, "project-id", "", "Project ID")
	resultsCmd.Flags().StringVarP(&resultType, "type", "t", "sast", "Result type (sast or iac)")
	resultsCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to fetch")
	resultsCmd.Flags().BoolVarP(&allResults, "all", "a", false, "Fetch all results")
	resultsCmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format (json, html, sarif)")
	resultsCmd.Flags().StringVarP(&outputFile, "filename", "f", "results.json", "Output file name")
	resultsCmd.Flags().StringVar(&outputPath, "filepath", ".", "Output file path")
}

func executeResultsCommand(cmd *cobra.Command, args []string) {
	pat := viper.GetString("pat")
	apiURL := viper.GetString("api_url")

	// Validate input arguments
	validateInputs(pat)

	// Adjust output file extensions based on format
	setOutputFileDefaults()

	logger.Info("Fetching results for project %s, type %s", projectIDResults, resultType)

	// Create the client and fetch results
	client := api.NewClient(apiURL, pat, config.LogtoEndpoint, config.LogtoClientID)

	var results *api.ScanResults
	if allResults {
		results = fetchAllResults(client)
	} else {
		results = fetchResults(client, page)
	}

	// Output results in the specified format
	outputResults(results)
}

func validateInputs(pat string) {
	if pat == "" {
		logger.Error("authentication required: provide a PAT via --pat flag, CYBEDEFEND_PAT env variable, or pat field in config file. Create one at Account Settings → Personal Access Tokens")
		os.Exit(1)
	}

	if projectIDResults == "" {
		projectIDResults = viper.GetString("project_id")
		if projectIDResults == "" {
			logger.Error("Project ID is required. Use --project-id flag or set CYBEDEFEND_PROJECT_ID environment variable.")
			os.Exit(1)
		}
	}

	if outputFormat != "json" && outputFormat != "html" && outputFormat != "sarif" {
		logger.Error("Invalid output format: %s. Use 'json', 'html', or 'sarif'.", outputFormat)
		os.Exit(1)
	}

	if page < 1 && !allResults {
		logger.Error("Invalid page number: %d. Must be greater than 0.", page)
		os.Exit(1)
	}

	if resultType != "sast" && resultType != "iac" {
		logger.Error("Invalid result type: %s. Use 'sast' or 'iac'.", resultType)
		os.Exit(1)
	}
}

func setOutputFileDefaults() {
	switch outputFormat {
	case "html":
		if filepath.Ext(outputFile) != ".html" {
			outputFile = "results.html"
		}
	case "sarif":
		if filepath.Ext(outputFile) != ".sarif" {
			outputFile = "results.sarif"
		}
	case "json":
		if filepath.Ext(outputFile) != ".json" {
			outputFile = "results.json"
		}
	}
}

func fetchResults(client *api.Client, page int) *api.ScanResults {
	results, err := client.GetResults(projectIDResults, resultType, page, 20)
	if err != nil {
		logger.Error("Error fetching results: %v", err)
		os.Exit(1)
	}

	if page > results.TotalPages {
		logger.Warn("Requested page %d exceeds total pages (%d). Fetching last page instead.", page, results.TotalPages)
		results, err = client.GetResults(projectIDResults, resultType, results.TotalPages, 20)
		if err != nil {
			logger.Error("Error fetching last page: %v", err)
			os.Exit(1)
		}
	}

	return results
}

func fetchAllResults(client *api.Client) *api.ScanResults {
	allResults := &api.ScanResults{}
	page := 1

	projectName := ""

	for {
		logger.Info("Fetching page %d...", page)
		results, err := client.GetResults(projectIDResults, resultType, page, 100)
		if err != nil {
			logger.Error("Error fetching page %d: %v", page, err)
			os.Exit(1)
		}
		if projectName == "" {
			projectName = results.ProjectName
		}

		allResults.Vulnerabilities = append(allResults.Vulnerabilities, results.Vulnerabilities...)

		if allResults.Severity == nil {
			allResults.Total = results.Total
		}

		if page >= results.TotalPages {
			break
		}
		page++
		time.Sleep(1 * time.Second)
	}

	allResults.ProjectID = projectIDResults
	allResults.ProjectName = projectName
	allResults.TotalPages = page
	return allResults
}

func outputResults(results *api.ScanResults) {
	outputFilePath := filepath.Join(outputPath, outputFile)

	switch outputFormat {
	case "json":
		writeJSONOutput(results, outputFilePath)
	case "html":
		writeHTMLOutput(results, outputFilePath)
	case "sarif":
		writeSARIFOutput(results, outputFilePath)
	default:
		logger.Error("Unsupported output format: %s.", outputFormat)
		os.Exit(1)
	}

	logger.Success("Results saved successfully to %s", outputFilePath)
}

func writeJSONOutput(results *api.ScanResults, filePath string) {
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

func writeHTMLOutput(results *api.ScanResults, filePath string) {
	report := utils.VulnerabilityReport{
		ProjectName:       results.ProjectName,
		ProjectID:         results.ProjectID,
		Total:             results.Total,
		Page:              results.Page,
		TotalPages:        results.TotalPages,
		Severity:          results.Severity,
		Vulnerabilities:   mapVulnerabilities(results.Vulnerabilities),
		VulnerabilityType: resultType,
	}

	err := utils.RenderHTMLReport(report, filePath)
	if err != nil {
		logger.Error("Error generating HTML report: %v", err)
		os.Exit(1)
	}
}

func writeSARIFOutput(results *api.ScanResults, filePath string) {
	report := utils.VulnerabilityReport{
		ProjectName:       results.ProjectName,
		ProjectID:         results.ProjectID,
		Total:             results.Total,
		Page:              results.Page,
		TotalPages:        results.TotalPages,
		Severity:          results.Severity,
		Vulnerabilities:   mapVulnerabilities(results.Vulnerabilities),
		VulnerabilityType: resultType,
	}

	err := utils.ConvertToSARIF(report, filePath)
	if err != nil {
		logger.Error("Error generating SARIF report: %v", err)
		os.Exit(1)
	}
}

func mapVulnerabilities(apiVulns []api.Vulnerability) []utils.Vulnerability {
	var utilsVulns []utils.Vulnerability
	for _, v := range apiVulns {
		utilsVulns = append(utilsVulns, utils.Vulnerability{
			ID:                  v.ID,
			Name:                v.Details.Name,
			Description:         strings.ReplaceAll(v.Details.Description, "**", ""),
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
