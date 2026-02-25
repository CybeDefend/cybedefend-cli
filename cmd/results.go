package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/auth"
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
	resultType       string // sast | sca | iac | secret | cicd | container | all
	page             int
	outputFormat     string // json | html | sarif
	outputFile       string
	outputPath       string
	allResults       bool
	resultsBranch    string
	groupedMode      bool
)

var resultsCmd = &cobra.Command{
	Use:   "results",
	Short: "Get scan results",
	Run:   executeResultsCommand,
}

func init() {
	resultsCmd.Flags().StringVar(&projectIDResults, "project-id", "", "Project ID")
	resultsCmd.Flags().StringVarP(&resultType, "type", "t", "all", "Scan type (sast, sca, iac, secret, cicd, container, all)")
	resultsCmd.Flags().IntVarP(&page, "page", "p", 1, "Page number to fetch")
	resultsCmd.Flags().BoolVarP(&allResults, "all", "a", true, "Fetch all pages")
	resultsCmd.Flags().StringVarP(&outputFormat, "output", "o", "json", "Output format (json, html, sarif)")
	resultsCmd.Flags().StringVarP(&outputFile, "filename", "f", "results.json", "Output file name")
	resultsCmd.Flags().StringVar(&outputPath, "filepath", ".", "Output file path")
	resultsCmd.Flags().StringVarP(&resultsBranch, "branch", "b", "", "Branch to filter results (default: all branches)")
	resultsCmd.Flags().BoolVarP(&groupedMode, "grouped", "g", false, "Return results grouped by rule/CVE")
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

func executeResultsCommand(cmd *cobra.Command, args []string) {
	pat := viper.GetString("pat")
	validateInputs(pat)
	setOutputFileDefaults()

	client := newClientFromConfig()

	switch {
	case resultType == "all":
		// "all" always uses flat endpoints and outputs a typed JSON map.
		executeAllTypesResults(client)

	case groupedMode && resultType == "container":
		// Container has its own grouped endpoint shape.
		executeContainerGroupedResults(client)

	case groupedMode:
		// sast/grouped, iac/grouped, sca/grouped, secret/grouped, cicd/grouped
		executeGroupedResults(client)

	default:
		// Standard flat paged results.
		executeStandardResults(client)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Standard flat results
// ─────────────────────────────────────────────────────────────────────────────

func executeStandardResults(client *api.Client) {
	if resultsBranch != "" {
		logger.Info("Fetching results for project %s, type %s, branch %s", projectIDResults, resultType, resultsBranch)
	} else {
		logger.Info("Fetching results for project %s, type %s", projectIDResults, resultType)
	}

	var results *api.ScanResults
	if allResults {
		results = fetchAllPages(client, resultType)
	} else {
		results = fetchOnePage(client, resultType, page)
	}
	outputResults(results)
}

func fetchOnePage(client *api.Client, scanType string, pg int) *api.ScanResults {
	results, err := client.GetResults(projectIDResults, scanType, pg, 20, resultsBranch)
	if err != nil {
		logger.Error("Error fetching results: %v", err)
		os.Exit(1)
	}
	if results.TotalPages == 0 {
		logger.Info("No results found for this project.")
		return results
	}
	if pg > results.TotalPages {
		logger.Warn("Requested page %d exceeds total pages (%d). Fetching last page instead.", pg, results.TotalPages)
		results, err = client.GetResults(projectIDResults, scanType, results.TotalPages, 20, resultsBranch)
		if err != nil {
			logger.Error("Error fetching last page: %v", err)
			os.Exit(1)
		}
	}
	return results
}

func fetchAllPages(client *api.Client, scanType string) *api.ScanResults {
	combined := &api.ScanResults{}
	projectName := ""
	for pg := 1; ; pg++ {
		logger.Info("Fetching page %d...", pg)
		res, err := client.GetResults(projectIDResults, scanType, pg, 100, resultsBranch)
		if err != nil {
			logger.Error("Error fetching page %d: %v", pg, err)
			os.Exit(1)
		}
		if projectName == "" {
			projectName = res.ProjectName
		}
		combined.Vulnerabilities = append(combined.Vulnerabilities, res.Vulnerabilities...)
		if combined.Total == 0 {
			combined.Total = res.Total
		}
		if pg >= res.TotalPages {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	combined.ProjectID = projectIDResults
	combined.ProjectName = projectName
	combined.TotalPages = 1
	combined.Page = 1
	return combined
}

// ─────────────────────────────────────────────────────────────────────────────
// Grouped results
// ─────────────────────────────────────────────────────────────────────────────

func executeGroupedResults(client *api.Client) {
	if resultsBranch != "" {
		logger.Info("Fetching grouped results for project %s, type %s, branch %s", projectIDResults, resultType, resultsBranch)
	} else {
		logger.Info("Fetching grouped results for project %s, type %s", projectIDResults, resultType)
	}

	if outputFormat != "json" {
		logger.Error("Grouped mode only supports JSON output (--output json).")
		os.Exit(1)
	}

	var combined *api.GroupedScanResults
	if allResults {
		combined = fetchAllGroupedPages(client)
	} else {
		res, err := client.GetGroupedResults(projectIDResults, resultType, page, 50, resultsBranch)
		if err != nil {
			logger.Error("Error fetching grouped results: %v", err)
			os.Exit(1)
		}
		combined = res
	}

	writeJSONAny(combined, filepath.Join(outputPath, outputFile))
	logger.Success("Results saved successfully to %s", filepath.Join(outputPath, outputFile))
}

func fetchAllGroupedPages(client *api.Client) *api.GroupedScanResults {
	combined := &api.GroupedScanResults{}
	for pg := 1; ; pg++ {
		logger.Info("Fetching grouped page %d...", pg)
		res, err := client.GetGroupedResults(projectIDResults, resultType, pg, 100, resultsBranch)
		if err != nil {
			logger.Error("Error fetching grouped page %d: %v", pg, err)
			os.Exit(1)
		}
		if pg == 1 {
			combined.ProjectID = res.ProjectID
			combined.ProjectName = res.ProjectName
			combined.Total = res.Total
			combined.TotalOccurrences = res.TotalOccurrences
			combined.Sort = res.Sort
			combined.Order = res.Order
			combined.Severity = res.Severity
			combined.Status = res.Status
			combined.Priority = res.Priority
		}
		combined.GroupedVulnerabilities = append(combined.GroupedVulnerabilities, res.GroupedVulnerabilities...)
		if pg >= res.TotalPages {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	combined.Page = 1
	combined.TotalPages = 1
	combined.Limit = len(combined.GroupedVulnerabilities)
	return combined
}

// ─────────────────────────────────────────────────────────────────────────────
// Container grouped results
// ─────────────────────────────────────────────────────────────────────────────

func executeContainerGroupedResults(client *api.Client) {
	if resultsBranch != "" {
		logger.Info("Fetching grouped container images for project %s, branch %s", projectIDResults, resultsBranch)
	} else {
		logger.Info("Fetching grouped container images for project %s", projectIDResults)
	}

	if outputFormat != "json" {
		logger.Error("Grouped mode only supports JSON output (--output json).")
		os.Exit(1)
	}

	var combined *api.ContainerGroupedResults
	if allResults {
		combined = fetchAllContainerGroupedPages(client)
	} else {
		res, err := client.GetContainerGroupedResults(projectIDResults, page, 50, resultsBranch)
		if err != nil {
			logger.Error("Error fetching container grouped results: %v", err)
			os.Exit(1)
		}
		combined = res
	}

	writeJSONAny(combined, filepath.Join(outputPath, outputFile))
	logger.Success("Results saved successfully to %s", filepath.Join(outputPath, outputFile))
}

func fetchAllContainerGroupedPages(client *api.Client) *api.ContainerGroupedResults {
	combined := &api.ContainerGroupedResults{}
	for pg := 1; ; pg++ {
		logger.Info("Fetching container grouped page %d...", pg)
		res, err := client.GetContainerGroupedResults(projectIDResults, pg, 100, resultsBranch)
		if err != nil {
			logger.Error("Error fetching container grouped page %d: %v", pg, err)
			os.Exit(1)
		}
		if pg == 1 {
			combined.ProjectName = res.ProjectName
			combined.TotalRepositories = res.TotalRepositories
			combined.TotalTags = res.TotalTags
		}
		combined.GroupedImages = append(combined.GroupedImages, res.GroupedImages...)
		if pg >= res.TotalPages {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	combined.CurrentPage = 1
	combined.TotalPages = 1
	combined.PageSize = len(combined.GroupedImages)
	return combined
}

// ─────────────────────────────────────────────────────────────────────────────
// "all" type results
// ─────────────────────────────────────────────────────────────────────────────

var allScanTypes = []string{"sast", "sca", "iac", "secret", "cicd", "container"}

func executeAllTypesResults(client *api.Client) {
	if outputFormat != "json" {
		logger.Error("'all' type only supports JSON output (--output json).")
		os.Exit(1)
	}

	logger.Info("Fetching all scan types for project %s", projectIDResults)

	combined := &api.AllScanResults{
		ProjectID: projectIDResults,
		SAST:      []api.Vulnerability{},
		SCA:       []api.Vulnerability{},
		IAC:       []api.Vulnerability{},
		Secret:    []api.Vulnerability{},
		CICD:      []api.Vulnerability{},
		Container: []api.Vulnerability{},
	}
	for _, t := range allScanTypes {
		logger.Info("Fetching %s results...", t)
		vulns := fetchAllPagesForType(client, t)
		if combined.ProjectName == "" {
			combined.ProjectName = vulns.ProjectName
		}
		switch t {
		case "sast":
			combined.SAST = vulns.Vulnerabilities
		case "sca":
			combined.SCA = vulns.Vulnerabilities
		case "iac":
			combined.IAC = vulns.Vulnerabilities
		case "secret":
			combined.Secret = vulns.Vulnerabilities
		case "cicd":
			combined.CICD = vulns.Vulnerabilities
		case "container":
			combined.Container = vulns.Vulnerabilities
		}
		time.Sleep(300 * time.Millisecond)
	}

	writeJSONAny(combined, filepath.Join(outputPath, outputFile))
	logger.Success("Results saved successfully to %s", filepath.Join(outputPath, outputFile))
}

func fetchAllPagesForType(client *api.Client, scanType string) *api.ScanResults {
	combined := &api.ScanResults{
		Vulnerabilities: []api.Vulnerability{},
	}
	for pg := 1; ; pg++ {
		res, err := client.GetResults(projectIDResults, scanType, pg, 100, resultsBranch)
		if err != nil {
			logger.Warn("Could not fetch %s results (page %d): %v", scanType, pg, err)
			break
		}
		if combined.ProjectName == "" {
			combined.ProjectName = res.ProjectName
		}
		combined.Vulnerabilities = append(combined.Vulnerabilities, res.Vulnerabilities...)
		if pg >= res.TotalPages || res.TotalPages == 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	return combined
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation & helpers
// ─────────────────────────────────────────────────────────────────────────────

func validateInputs(pat string) {
	if pat == "" {
		creds, err := auth.LoadCredentials()
		if err != nil || creds == nil {
			logger.Error("authentication required: run 'cybedefend login', or provide a PAT via --pat flag, CYBEDEFEND_PAT env variable, or pat field in config file")
			os.Exit(1)
		}
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

	validTypes := api.ValidScanTypes
	valid := false
	for _, v := range validTypes {
		if resultType == v {
			valid = true
			break
		}
	}
	if !valid {
		logger.Error("Invalid scan type: %s. Use one of: %s", resultType, strings.Join(validTypes, ", "))
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

// ─────────────────────────────────────────────────────────────────────────────
// Output writers
// ─────────────────────────────────────────────────────────────────────────────

func outputResults(results *api.ScanResults) {
	outputFilePath := filepath.Join(outputPath, outputFile)
	switch outputFormat {
	case "json":
		writeJSONAny(results, outputFilePath)
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

func writeJSONAny(v any, filePath string) {
	file, err := os.Create(filePath)
	if err != nil {
		logger.Error("Error creating file: %v", err)
		os.Exit(1)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		logger.Error("Error writing JSON: %v", err)
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
	if err := utils.RenderHTMLReport(report, filePath); err != nil {
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
	if err := utils.ConvertToSARIF(report, filePath); err != nil {
		logger.Error("Error generating SARIF report: %v", err)
		os.Exit(1)
	}
}

func mapVulnerabilities(apiVulns []api.Vulnerability) []utils.Vulnerability {
	var out []utils.Vulnerability
	for _, v := range apiVulns {
		out = append(out, utils.Vulnerability{
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
	return out
}
