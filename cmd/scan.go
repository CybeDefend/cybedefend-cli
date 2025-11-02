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
	scanDir         string
	scanFile        string
	projectIDScan   string
	waitForComplete bool
	breakOnFail     bool
	breakOnSeverity string
	scanInterval    int
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
		scanID, err := executeScan(client, projectIDScan, zipPath)
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
func executeScan(client *api.Client, projectID, zipPath string) (string, error) {
	scanResult, err := client.StartScan(projectID, zipPath)
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

	handleBreakOnSeverity(client, projectID, scanStatus)
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
	scanCmd.Flags().BoolVarP(&waitForComplete, "wait", "w", true, "Wait for scan to complete")
	scanCmd.Flags().BoolVar(&breakOnFail, "break-on-fail", false, "Exit with error code if scan fails")
	scanCmd.Flags().StringVar(&breakOnSeverity, "break-on-severity", "", "Exit with error code if vulnerabilities of specified severity or above are found (critical, high, medium, low, none)")
	scanCmd.Flags().IntVar(&scanInterval, "interval", 5, "Interval (in seconds) between scan status checks when waiting for completion")
}
