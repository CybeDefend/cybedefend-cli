package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// ── Parent command ───────────────────────────────────────────────────

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate security reports",
	Long:  "Generate SBOM, OWASP, CWE, organization, team, and batch reports.",
}

// ── report sbom ─────────────────────────────────────────────────────

var reportSBOMCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Download SBOM report for a project",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		output, _ := cmd.Flags().GetString("output")

		client := newClientFromConfig()
		data, err := client.GetSBOMReport(projectID)
		if err != nil {
			logger.Error("Failed to get SBOM report: %v", err)
			os.Exit(1)
		}

		if output == "" {
			output = fmt.Sprintf("sbom-%s.json", projectID)
		}

		writeReportFile(output, data)
	},
}

// ── report owasp ────────────────────────────────────────────────────

var reportOWASPCmd = &cobra.Command{
	Use:   "owasp",
	Short: "Generate OWASP report for a project",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		format, _ := cmd.Flags().GetString("format")
		detailed, _ := cmd.Flags().GetBool("detailed")
		output, _ := cmd.Flags().GetString("output")

		validateReportFormat(format)

		client := newClientFromConfig()
		data, err := client.GetOWASPReport(projectID, format, detailed)
		if err != nil {
			logger.Error("Failed to get OWASP report: %v", err)
			os.Exit(1)
		}

		if output == "" {
			output = fmt.Sprintf("owasp-report-%s.%s", projectID, format)
		}

		writeReportFile(output, data)
	},
}

// ── report cwe ──────────────────────────────────────────────────────

var reportCWECmd = &cobra.Command{
	Use:   "cwe",
	Short: "Generate CWE Top 25 report for a project",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		format, _ := cmd.Flags().GetString("format")
		detailed, _ := cmd.Flags().GetBool("detailed")
		output, _ := cmd.Flags().GetString("output")

		validateReportFormat(format)

		client := newClientFromConfig()
		data, err := client.GetCWEReport(projectID, format, detailed)
		if err != nil {
			logger.Error("Failed to get CWE report: %v", err)
			os.Exit(1)
		}

		if output == "" {
			output = fmt.Sprintf("cwe-report-%s.%s", projectID, format)
		}

		writeReportFile(output, data)
	},
}

// ── report org ──────────────────────────────────────────────────────

var reportOrgCmd = &cobra.Command{
	Use:   "org",
	Short: "Generate aggregated security report for an organization",
	Run: func(cmd *cobra.Command, args []string) {
		orgID, _ := cmd.Flags().GetString("organization-id")
		reportType, _ := cmd.Flags().GetString("type")
		format, _ := cmd.Flags().GetString("format")
		detailed, _ := cmd.Flags().GetBool("detailed")
		output, _ := cmd.Flags().GetString("output")

		if orgID == "" {
			logger.Error("--organization-id is required")
			os.Exit(1)
		}
		validateReportType(reportType)
		validateReportFormat(format)

		client := newClientFromConfig()
		data, err := client.GetOrgReport(orgID, reportType, format, detailed)
		if err != nil {
			logger.Error("Failed to get organization report: %v", err)
			os.Exit(1)
		}

		if output == "" {
			output = fmt.Sprintf("org-%s-%s.%s", reportType, orgID, format)
		}

		writeReportFile(output, data)
	},
}

// ── report team ─────────────────────────────────────────────────────

var reportTeamCmd = &cobra.Command{
	Use:   "team",
	Short: "Generate aggregated security report for a team",
	Run: func(cmd *cobra.Command, args []string) {
		teamID, _ := cmd.Flags().GetString("team-id")
		reportType, _ := cmd.Flags().GetString("type")
		format, _ := cmd.Flags().GetString("format")
		detailed, _ := cmd.Flags().GetBool("detailed")
		output, _ := cmd.Flags().GetString("output")

		if teamID == "" {
			logger.Error("--team-id is required")
			os.Exit(1)
		}
		validateReportType(reportType)
		validateReportFormat(format)

		client := newClientFromConfig()
		data, err := client.GetTeamReport(teamID, reportType, format, detailed)
		if err != nil {
			logger.Error("Failed to get team report: %v", err)
			os.Exit(1)
		}

		if output == "" {
			output = fmt.Sprintf("team-%s-%s.%s", reportType, teamID, format)
		}

		writeReportFile(output, data)
	},
}

// ── report batch ────────────────────────────────────────────────────

var reportBatchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Generate report for a manual selection of projects",
	Run: func(cmd *cobra.Command, args []string) {
		orgID, _ := cmd.Flags().GetString("organization-id")
		projectIDs, _ := cmd.Flags().GetString("project-ids")
		reportType, _ := cmd.Flags().GetString("type")
		format, _ := cmd.Flags().GetString("format")
		detailed, _ := cmd.Flags().GetBool("detailed")
		output, _ := cmd.Flags().GetString("output")

		if orgID == "" {
			logger.Error("--organization-id is required")
			os.Exit(1)
		}
		if projectIDs == "" {
			logger.Error("--project-ids is required (comma-separated)")
			os.Exit(1)
		}
		validateReportType(reportType)
		validateReportFormat(format)

		ids := strings.Split(projectIDs, ",")
		reqBody := &api.BatchReportRequest{
			ProjectIDs: ids,
			Detailed:   &detailed,
		}

		client := newClientFromConfig()
		data, suggestedFilename, err := client.GetBatchReport(orgID, reportType, format, reqBody)
		if err != nil {
			logger.Error("Failed to get batch report: %v", err)
			os.Exit(1)
		}

		if output == "" {
			if suggestedFilename != "" {
				output = suggestedFilename
			} else {
				output = fmt.Sprintf("batch-%s.%s", reportType, format)
			}
		}

		writeReportFile(output, data)
	},
}

// ── helpers ─────────────────────────────────────────────────────────

func validateReportFormat(format string) {
	switch format {
	case "json", "html", "pdf":
		// ok
	default:
		logger.Error("Invalid format: %s. Use 'json', 'html', or 'pdf'.", format)
		os.Exit(1)
	}
}

func validateReportType(reportType string) {
	switch reportType {
	case "owasp", "cwe":
		// ok
	default:
		logger.Error("Invalid report type: %s. Use 'owasp' or 'cwe'.", reportType)
		os.Exit(1)
	}
}

func writeReportFile(outputPath string, data []byte) {
	dir := filepath.Dir(outputPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Error("Error creating directory: %v", err)
			os.Exit(1)
		}
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		logger.Error("Error writing file: %v", err)
		os.Exit(1)
	}

	logger.Success("Report saved to %s (%d bytes)", outputPath, len(data))
}

// ── init ────────────────────────────────────────────────────────────

func init() {
	// report sbom
	reportSBOMCmd.Flags().String("project-id", "", "Project ID")
	reportSBOMCmd.Flags().String("output", "", "Output file path (default: sbom-<project-id>.json)")

	// report owasp
	reportOWASPCmd.Flags().String("project-id", "", "Project ID")
	reportOWASPCmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportOWASPCmd.Flags().Bool("detailed", false, "Include detailed information")
	reportOWASPCmd.Flags().String("output", "", "Output file path")

	// report cwe
	reportCWECmd.Flags().String("project-id", "", "Project ID")
	reportCWECmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportCWECmd.Flags().Bool("detailed", false, "Include detailed information")
	reportCWECmd.Flags().String("output", "", "Output file path")

	// report org
	reportOrgCmd.Flags().String("organization-id", "", "Organization ID (required)")
	reportOrgCmd.Flags().String("type", "owasp", "Report type: owasp, cwe")
	reportOrgCmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportOrgCmd.Flags().Bool("detailed", false, "Include detailed information")
	reportOrgCmd.Flags().String("output", "", "Output file path")

	// report team
	reportTeamCmd.Flags().String("team-id", "", "Team ID (required)")
	reportTeamCmd.Flags().String("type", "owasp", "Report type: owasp, cwe")
	reportTeamCmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportTeamCmd.Flags().Bool("detailed", false, "Include detailed information")
	reportTeamCmd.Flags().String("output", "", "Output file path")

	// report batch
	reportBatchCmd.Flags().String("organization-id", "", "Organization ID (required)")
	reportBatchCmd.Flags().String("project-ids", "", "Comma-separated project IDs (required)")
	reportBatchCmd.Flags().String("type", "owasp", "Report type: owasp, cwe")
	reportBatchCmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportBatchCmd.Flags().Bool("detailed", true, "Include detailed information")
	reportBatchCmd.Flags().String("output", "", "Output file path")

	// Register subcommands
	reportCmd.AddCommand(reportSBOMCmd)
	reportCmd.AddCommand(reportOWASPCmd)
	reportCmd.AddCommand(reportCWECmd)
	reportCmd.AddCommand(reportOrgCmd)
	reportCmd.AddCommand(reportTeamCmd)
	reportCmd.AddCommand(reportBatchCmd)
}
