package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/utils"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	scanDir             string
	scanFile            string
	projectIDScan       string
	scanBranch          string
	waitForComplete     bool
	breakOnFail         bool
	breakOnSeverity     string
	scanInterval        int
	enablePolicyCheck   bool
	policyCheckTimeout  int
	showPolicyVulns     bool
	showAllPolicyVulns  bool
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

		// Retrieve branch from config if not explicitly set via flag
		if !cmd.Flags().Changed("branch") {
			if configBranch := viper.GetString("branch"); configBranch != "" {
				scanBranch = configBranch
			}
		}

		if err := validateScanRequirements(apiKey, projectIDScan); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}

		zipPath, err := prepareZipFile()
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}

		if err := validateBreakOnSeverity(); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}

		client := api.NewClient(apiURL, apiKey)
		scanID, err := executeScan(client, projectIDScan, zipPath, scanBranch)
		if err != nil {
			logger.Error("Error starting scan: %v", err)
			os.Exit(1)
		}

		logger.Success("Scan started successfully. Scan ID: %s", scanID)

		if waitForComplete {
			handleScanCompletion(client, projectIDScan, scanID)
		}
	},
}

// validateScanRequirements checks if API key and project ID are provided
func validateScanRequirements(apiKey, projectID string) error {
	if apiKey == "" {
		return fmt.Errorf("API Key is required. Use --api-key flag, set CYBEDEFEND_API_KEY environment variable, or specify in config file")
	}
	if projectID == "" {
		return fmt.Errorf("Project ID is required. Use --project-id flag, set CYBEDEFEND_PROJECT_ID environment variable, or specify in config file")
	}
	return nil
}

// prepareZipFile creates or validates the zip file to be scanned
func prepareZipFile() (string, error) {
	if scanDir != "" && scanFile != "" {
		return "", fmt.Errorf("Please provide either a directory to scan using --dir or a zip file using --file, not both")
	}

	if scanDir != "" {
		logger.Info("Starting scan of directory: %s", scanDir)
		zipPath, err := utils.ZipDirectory(scanDir)
		if err != nil {
			return "", fmt.Errorf("Error zipping directory: %v", err)
		}
		return zipPath, nil
	}

	if scanFile != "" {
		logger.Info("Starting scan of a zip file directly: %s", scanFile)
		return scanFile, nil
	}

	return "", fmt.Errorf("Please provide a directory to scan using --dir or a zip file using --file")
}

// validateBreakOnSeverity checks if the provided severity level is valid
func validateBreakOnSeverity() error {
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
		"none":     true, // Add 'none' as a valid value to explicitly disable break on severity
	}
	breakOnSeverity = strings.ToLower(breakOnSeverity)
	if breakOnSeverity != "" && !validSeverities[breakOnSeverity] {
		return fmt.Errorf("Invalid severity level: %s. Use 'critical', 'high', 'medium', 'low', or 'none'", breakOnSeverity)
	}
	return nil
}

// executeScan starts the scan and handles cleanup of temporary files
func executeScan(client *api.Client, projectID, zipPath, branch string) (string, error) {
	scanResult, err := client.StartScan(projectID, zipPath, branch)
	if err != nil {
		return "", err
	}

	// Clean up temporary zip file if it was created from a directory
	if scanDir != "" {
		if err := os.Remove(zipPath); err != nil {
			logger.Error("Error removing temporary zip file: %v", err)
		} else {
			logger.Debug("Removed temporary zip file: %s", zipPath)
		}
	}

	return scanResult.GetScanID(), nil
}

// handleScanCompletion waits for scan completion and handles break conditions
func handleScanCompletion(client *api.Client, projectID, scanID string) {
	logger.Info("Waiting for scan to complete...")
	scanStatus, err := waitForScanToComplete(client, projectID, scanID, scanInterval)
	if err != nil {
		logger.Error("Error waiting for scan to complete: %v", err)
		os.Exit(1)
	}

	if breakOnFail && scanStatus.IsFailed() {
		logger.Error("Scan failed. Exiting with error code.")
		os.Exit(1)
	}

	// Skip policy check if scan failed
	if scanStatus.IsFailed() {
		logger.Info("Scan failed - skipping policy evaluation")
		return
	}

	handleBreakOnSeverity(client, projectID, scanStatus)

	// Handle policy evaluation if enabled
	if enablePolicyCheck {
		exitCode := handlePolicyEvaluation(client, projectID, scanID)
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}
}

// handleBreakOnSeverity checks vulnerabilities and exits if threshold is exceeded
func handleBreakOnSeverity(client *api.Client, projectID string, scanStatus *api.ScanStatus) {
	if breakOnSeverity == "" {
		return
	}

	if breakOnSeverity == "none" {
		showVulnerabilitySummary(client, projectID)
		logger.Info("Break on vulnerability severity is disabled (set to 'none')")
		return
	}

	if !scanStatus.IsCompleted() || scanStatus.IsFailed() {
		return
	}

	if hasVulnerabilitiesAtOrAboveSeverity(client, projectID, breakOnSeverity) {
		logger.Error("Found vulnerabilities with severity %s or above. Exiting with error code.", strings.ToUpper(breakOnSeverity))
		os.Exit(1)
	} else {
		logger.Success("No vulnerabilities found with severity %s or above.", strings.ToUpper(breakOnSeverity))
	}
}

// waitForScanToComplete polls the scan status until it completes or fails
func waitForScanToComplete(client *api.Client, projectID, scanID string, intervalSeconds int) (*api.ScanStatus, error) {
	for {
		scanStatus, err := client.GetScanStatus(projectID, scanID)
		if err != nil {
			return nil, err
		}

		logger.Info("Scan progress: %d%% - State: %s - Step: %s",
			scanStatus.Progress,
			scanStatus.State,
			scanStatus.Step)

		if scanStatus.IsCompleted() {
			if scanStatus.IsFailed() {
				logger.Error("Scan completed with status: FAILED")
			} else {
				logger.Success("Scan completed with status: %s", strings.ToUpper(scanStatus.State))
				logger.Info("Vulnerabilities detected: %d", scanStatus.VulnerabilityDetected)
			}
			return scanStatus, nil
		}

		// Wait before checking again
		time.Sleep(time.Duration(intervalSeconds) * time.Second)
	}
}

// hasVulnerabilitiesAtOrAboveSeverity checks if there are vulnerabilities at or above the specified severity level
func hasVulnerabilitiesAtOrAboveSeverity(client *api.Client, projectID, minSeverity string) bool {
	// Define severities to check based on the minimum severity specified
	var severitiesToCheck []string

	switch minSeverity {
	case "low":
		severitiesToCheck = []string{"low", "medium", "high", "critical"}
	case "medium":
		severitiesToCheck = []string{"medium", "high", "critical"}
	case "high":
		severitiesToCheck = []string{"high", "critical"}
	case "critical":
		severitiesToCheck = []string{"critical"}
	}

	// Get vulnerabilities by severity
	vulnerabilities, err := client.GetVulnerabilitiesBySeverity(projectID, "sast", severitiesToCheck)
	if err != nil {
		logger.Error("Error retrieving vulnerabilities: %v", err)
		// In case of error, assume there are vulnerabilities to be safe
		return true
	}

	// Count total vulnerabilities
	totalVulnerabilities := 0

	// Log detailed information for each severity level
	logger.Info("Vulnerability breakdown (excluding resolved or not_exploitable):")
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		if count, exists := vulnerabilities[severity]; exists && count > 0 {
			totalVulnerabilities += count
			logger.Info(" - %s: %d", strings.ToUpper(severity), count)
		}
	}

	if totalVulnerabilities > 0 {
		logger.Info("Found %d total vulnerabilities at or above %s severity", totalVulnerabilities, strings.ToUpper(minSeverity))
		return true
	} else {
		logger.Success("No vulnerabilities found at or above %s severity", strings.ToUpper(minSeverity))
		return false
	}
}

// showVulnerabilitySummary displays a summary of vulnerabilities without breaking the build
func showVulnerabilitySummary(client *api.Client, projectID string) {
	// Check all severity levels
	severitiesToCheck := []string{"critical", "high", "medium", "low"}

	// Get vulnerabilities by severity
	vulnerabilities, err := client.GetVulnerabilitiesBySeverity(projectID, "sast", severitiesToCheck)
	if err != nil {
		logger.Error("Error retrieving vulnerabilities: %v", err)
		return
	}

	// Log detailed information for each severity level
	totalVulnerabilities := 0
	logger.Info("Vulnerability breakdown (excluding resolved or not_exploitable):")
	for _, severity := range severitiesToCheck {
		if count, exists := vulnerabilities[severity]; exists {
			totalVulnerabilities += count
			if count > 0 {
				logger.Info(" - %s: %d", strings.ToUpper(severity), count)
			}
		}
	}

	if totalVulnerabilities > 0 {
		logger.Info("Found %d total vulnerabilities", totalVulnerabilities)
	} else {
		logger.Success("No vulnerabilities found")
	}
}

func init() {
	scanCmd.Flags().StringVarP(&scanDir, "dir", "d", "", "Directory to scan")
	scanCmd.Flags().StringVarP(&scanFile, "file", "f", "", "Zip file to scan")
	scanCmd.Flags().StringVar(&projectIDScan, "project-id", "", "Project ID")
	scanCmd.Flags().StringVarP(&scanBranch, "branch", "b", "main", "Branch name for the scan (e.g., main, develop)")
	scanCmd.Flags().BoolVarP(&waitForComplete, "wait", "w", true, "Wait for scan to complete")
	scanCmd.Flags().BoolVar(&breakOnFail, "break-on-fail", false, "Exit with error code if scan fails")
	scanCmd.Flags().StringVar(&breakOnSeverity, "break-on-severity", "", "Exit with error code if vulnerabilities of specified severity or above are found (critical, high, medium, low, none)")
	scanCmd.Flags().IntVar(&scanInterval, "interval", 5, "Interval (in seconds) between scan status checks when waiting for completion")
	scanCmd.Flags().BoolVar(&enablePolicyCheck, "policy-check", true, "Enable policy evaluation after scan")
	scanCmd.Flags().IntVar(&policyCheckTimeout, "policy-timeout", 300, "Timeout in seconds for policy evaluation")
	scanCmd.Flags().BoolVar(&showPolicyVulns, "show-policy-vulns", true, "Show affected vulnerabilities in policy evaluation output")
	scanCmd.Flags().BoolVar(&showAllPolicyVulns, "show-all-policy-vulns", false, "Show all affected vulnerabilities (no limit)")
}

// handlePolicyEvaluation handles the policy evaluation flow after scan completion
func handlePolicyEvaluation(client *api.Client, projectId, scanId string) int {
	logger.Info("Checking policy evaluation status...")

	// 1. Poll evaluation-status endpoint until COMPLETED or FAILED or timeout
	evalStatus, err := waitForPolicyEvaluation(client, projectId, scanId, policyCheckTimeout)
	if err != nil {
		logger.Error("Policy evaluation error: %v", err)
		return 1
	}

	if evalStatus.Status == "NOT_STARTED" {
		logger.Info("No policies configured for this project")
		return 0
	}

	if evalStatus.Status == "FAILED" {
		logger.Error("Policy evaluation failed: %s", evalStatus.Message)
		return 1
	}

	if !evalStatus.HasEvaluation {
		logger.Info("No policy evaluation available")
		return 0
	}

	// 2. Fetch all violations (handle pagination)
	violations, err := client.GetAllViolations(projectId, scanId)
	if err != nil {
		logger.Error("Failed to fetch violations: %v", err)
		return 1
	}

	if len(violations) == 0 {
		logger.Success("✓ Policy check passed - No violations found")
		return 0
	}

	// 3. Display violations and determine exit code
	return displayViolationsAndGetExitCode(violations)
}

// waitForPolicyEvaluation polls the evaluation status until completed or timeout
func waitForPolicyEvaluation(client *api.Client, projectId, scanId string, timeoutSec int) (*api.EvaluationStatus, error) {
	startTime := time.Now()
	pollInterval := 2 * time.Second

	for {
		elapsed := time.Since(startTime)
		if elapsed > time.Duration(timeoutSec)*time.Second {
			return nil, fmt.Errorf("policy evaluation timed out after %d seconds", timeoutSec)
		}

		status, err := client.GetEvaluationStatus(projectId, scanId)
		if err != nil {
			return nil, err
		}

		logger.Debug("Policy evaluation status: %s (progress: %d%%)", status.Status, status.Progress)

		// Terminal states
		if status.Status == "COMPLETED" || status.Status == "FAILED" || status.Status == "NOT_STARTED" {
			return status, nil
		}

		// Show progress for long evaluations
		if status.Status == "IN_PROGRESS" {
			logger.Info("Policy evaluation in progress: %d%%", status.Progress)
		}

		time.Sleep(pollInterval)
	}
}

// displayViolationsAndGetExitCode displays violations and returns appropriate exit code
func displayViolationsAndGetExitCode(violations []api.PolicyViolation) int {
	blockCount := 0
	warnCount := 0
	acknowledgedBlockCount := 0

	// Group violations by action (acknowledged BLOCK violations don't block the build)
	var blockViolations, warnViolations, acknowledgedViolations []api.PolicyViolation
	for _, v := range violations {
		if v.ActionTaken == "BLOCK" {
			if v.Acknowledged {
				acknowledgedViolations = append(acknowledgedViolations, v)
				acknowledgedBlockCount++
			} else {
				blockViolations = append(blockViolations, v)
				blockCount++
			}
		} else {
			warnViolations = append(warnViolations, v)
			warnCount++
		}
	}

	// Display BLOCK violations (in red)
	if len(blockViolations) > 0 {
		logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Error("🚫 BLOCKING VIOLATIONS (%d)", blockCount)
		logger.Error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		for _, v := range blockViolations {
			displayViolation(v, true)
		}
	}

	// Display acknowledged violations (in yellow - they don't block)
	if len(acknowledgedViolations) > 0 {
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Warn("✓ ACKNOWLEDGED VIOLATIONS (%d)", acknowledgedBlockCount)
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		for _, v := range acknowledgedViolations {
			displayAcknowledgedViolation(v)
		}
	}

	// Display WARN violations (in yellow)
	if len(warnViolations) > 0 {
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Warn("⚠️  WARNING VIOLATIONS (%d)", warnCount)
		logger.Warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		for _, v := range warnViolations {
			displayViolation(v, false)
		}
	}

	// Summary
	logger.Info("")
	logger.Info("Policy Evaluation Summary:")
	logger.Info("  • Total violations: %d", len(violations))
	if blockCount > 0 {
		logger.Error("  • Blocking: %d", blockCount)
	}
	if acknowledgedBlockCount > 0 {
		logger.Info("  • Acknowledged (not blocking): %d", acknowledgedBlockCount)
	}
	if warnCount > 0 {
		logger.Warn("  • Warnings: %d", warnCount)
	}

	// Return exit code based on non-acknowledged BLOCK violations only
	if blockCount > 0 {
		logger.Error("")
		logger.Error("❌ Build blocked due to %d policy violation(s)", blockCount)
		return 1 // Exit code 1 = build fails
	}

	logger.Success("")
	if acknowledgedBlockCount > 0 {
		logger.Success("✓ Policy check passed (%d acknowledged, %d warning(s))", acknowledgedBlockCount, warnCount)
	} else {
		logger.Success("✓ Policy check passed (with %d warning(s))", warnCount)
	}
	return 0
}

// displayAcknowledgedViolation displays an acknowledged violation
func displayAcknowledgedViolation(v api.PolicyViolation) {
	prefix := "  "
	description := v.Rule.Description
	if description == "" {
		description = fmt.Sprintf("%s %v", v.Rule.Type, v.Rule.Value)
	}
	
	logger.Warn("%s• [%s] %s", prefix, v.Rule.Name, description)
	logger.Warn("%s  Affected vulnerabilities: %d", prefix, v.AffectedVulnerabilitiesCount)
	logger.Warn("%s  ✓ Acknowledged: %s", prefix, v.AcknowledgementReason)

	// Display affected vulnerabilities with links
	displayAffectedVulnerabilities(v, false)
}

// displayViolation displays a single violation
func displayViolation(v api.PolicyViolation, isBlock bool) {
	prefix := "  "
	description := v.Rule.Description
	if description == "" {
		description = fmt.Sprintf("%s %v", v.Rule.Type, v.Rule.Value)
	}
	
	if isBlock {
		logger.Error("%s• [%s] %s", prefix, v.Rule.Name, description)
		logger.Error("%s  Affected vulnerabilities: %d", prefix, v.AffectedVulnerabilitiesCount)
	} else {
		logger.Warn("%s• [%s] %s", prefix, v.Rule.Name, description)
		logger.Warn("%s  Affected vulnerabilities: %d", prefix, v.AffectedVulnerabilitiesCount)
		if v.Acknowledged {
			logger.Warn("%s  ✓ Acknowledged: %s", prefix, v.AcknowledgementReason)
		}
	}

	// Display affected vulnerabilities with links
	displayAffectedVulnerabilities(v, isBlock)
}

// displayAffectedVulnerabilities displays the list of affected vulnerabilities with links
func displayAffectedVulnerabilities(v api.PolicyViolation, isBlock bool) {
	// Check if we should display vulnerabilities
	if !showPolicyVulns {
		return
	}

	if len(v.AffectedVulnerabilities) == 0 {
		return
	}

	appBaseURL := getAppBaseURL()
	projectId := v.ProjectId

	// Determine max vulnerabilities to display
	displayCount := len(v.AffectedVulnerabilities)
	maxDisplay := 5
	if showAllPolicyVulns {
		maxDisplay = displayCount
	}
	if displayCount > maxDisplay {
		displayCount = maxDisplay
	}

	for i := 0; i < displayCount; i++ {
		vuln := v.AffectedVulnerabilities[i]
		
		// Build the link - ensure vulnerabilityType is not empty
		vulnType := vuln.VulnerabilityType
		if vulnType == "" {
			vulnType = "sast" // Default to sast if not specified
		}
		link := fmt.Sprintf("%s/project/%s/%s/issue/%s", appBaseURL, projectId, vulnType, vuln.ID)
		
		// Format vulnerability info: name, filePath, startLine-endLine, severity
		var vulnInfo string
		if vuln.VulnerabilityType == "sca" && vuln.PackageName != "" {
			vulnInfo = fmt.Sprintf("%s - %s@%s", vuln.Name, vuln.PackageName, vuln.PackageVersion)
		} else {
			// SAST format: name, filePath, startLine-endLine
			if vuln.EndLine > 0 && vuln.EndLine != vuln.StartLine {
				vulnInfo = fmt.Sprintf("%s - %s (L%d-%d)", vuln.Name, vuln.FilePath, vuln.StartLine, vuln.EndLine)
			} else {
				vulnInfo = fmt.Sprintf("%s - %s (L%d)", vuln.Name, vuln.FilePath, vuln.StartLine)
			}
		}

		if isBlock {
			logger.Error("      → [%s] %s", vuln.Severity, vulnInfo)
			logger.Error("        %s", link)
		} else {
			logger.Warn("      → [%s] %s", vuln.Severity, vulnInfo)
			logger.Warn("        %s", link)
		}
	}

	// Show remaining count if there are more
	if len(v.AffectedVulnerabilities) > maxDisplay {
		remaining := len(v.AffectedVulnerabilities) - maxDisplay
		if isBlock {
			logger.Error("      ... and %d more vulnerabilities", remaining)
		} else {
			logger.Warn("      ... and %d more vulnerabilities", remaining)
		}
	}
}

// getAppBaseURL returns the base URL for the web application based on configuration
func getAppBaseURL() string {
	// Check if app_url is set in config
	appURL := viper.GetString("app_url")
	if appURL != "" {
		return strings.TrimSuffix(appURL, "/")
	}

	// Derive from region
	region := strings.ToLower(viper.GetString("region"))
	switch region {
	case "eu":
		return "https://eu.cybedefend.com"
	default:
		return "https://us.cybedefend.com"
	}
}
