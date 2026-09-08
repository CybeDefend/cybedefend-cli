package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/validation"
	"fmt"
	"os"
	"path/filepath"
	"time"

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

		wait := reportWait(cmd, validation.ReportInput{Output: output})

		client := newClientFromConfig()
		data, suggested, err := client.GetSBOMReport(projectID, wait)
		if err != nil {
			logger.Error("Failed to get SBOM report: %v", err)
			os.Exit(1)
		}

		writeReportFile(resolveReportOutput(output, suggested, fmt.Sprintf("sbom-%s.json", projectID)), data)
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

		wait := reportWait(cmd, validation.ReportInput{Format: format, Output: output})

		client := newClientFromConfig()
		data, suggested, err := client.GetOWASPReport(projectID, format, detailed, wait)
		if err != nil {
			logger.Error("Failed to get OWASP report: %v", err)
			os.Exit(1)
		}

		writeReportFile(resolveReportOutput(output, suggested, fmt.Sprintf("owasp-report-%s.%s", projectID, format)), data)
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

		wait := reportWait(cmd, validation.ReportInput{Format: format, Output: output})

		client := newClientFromConfig()
		data, suggested, err := client.GetCWEReport(projectID, format, detailed, wait)
		if err != nil {
			logger.Error("Failed to get CWE report: %v", err)
			os.Exit(1)
		}

		writeReportFile(resolveReportOutput(output, suggested, fmt.Sprintf("cwe-report-%s.%s", projectID, format)), data)
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

		requireID("--organization-id", orgID)
		wait := reportWait(cmd, validation.ReportInput{
			OrganizationID: orgID,
			ReportType:     reportType,
			Format:         format,
			Output:         output,
		})

		client := newClientFromConfig()
		data, suggested, err := client.GetOrgReport(orgID, reportType, format, detailed, wait)
		if err != nil {
			logger.Error("Failed to get organization report: %v", err)
			os.Exit(1)
		}

		writeReportFile(resolveReportOutput(output, suggested, fmt.Sprintf("org-%s-%s.%s", reportType, orgID, format)), data)
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

		requireID("--team-id", teamID)
		wait := reportWait(cmd, validation.ReportInput{
			TeamID:     teamID,
			ReportType: reportType,
			Format:     format,
			Output:     output,
		})

		client := newClientFromConfig()
		data, suggested, err := client.GetTeamReport(teamID, reportType, format, detailed, wait)
		if err != nil {
			logger.Error("Failed to get team report: %v", err)
			os.Exit(1)
		}

		writeReportFile(resolveReportOutput(output, suggested, fmt.Sprintf("team-%s-%s.%s", reportType, teamID, format)), data)
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

		requireID("--organization-id", orgID)
		if projectIDs == "" {
			logger.Error("--project-ids is required (comma-separated)")
			os.Exit(1)
		}

		ids := splitCSV(projectIDs)

		wait := reportWait(cmd, validation.ReportInput{
			OrganizationID: orgID,
			ProjectIDs:     ids,
			ReportType:     reportType,
			Format:         format,
			Output:         output,
		})

		reqBody := &api.BatchReportRequest{
			ProjectIDs: ids,
			Detailed:   &detailed,
		}

		client := newClientFromConfig()
		data, suggested, err := client.GetBatchReport(orgID, reportType, format, reqBody, wait)
		if err != nil {
			logger.Error("Failed to get batch report: %v", err)
			os.Exit(1)
		}

		writeReportFile(resolveReportOutput(output, suggested, fmt.Sprintf("batch-%s.%s", reportType, format)), data)
	},
}

// ── helpers ─────────────────────────────────────────────────────────

// validateReportInput checks the flags a report subcommand was given. Which id
// a subcommand needs is its own business — the required ones are asserted at the
// call site — so what is checked here is that every value that *was* given is
// one the report URL, the request body and the output path can carry.
func validateReportInput(input validation.ReportInput) {
	if err := validation.Struct(input); err != nil {
		logger.Error("%s", err)
		os.Exit(1)
	}
}

// reportWait validates everything a report subcommand was given and returns how
// long it may wait for the API to finish generating. The two belong together:
// --timeout is part of the same schema as the rest of the flags, and a report
// command has nothing to do before both are settled.
func reportWait(cmd *cobra.Command, input validation.ReportInput) time.Duration {
	seconds, _ := cmd.Flags().GetInt("timeout")
	input.TimeoutSeconds = seconds
	validateReportInput(input)
	return time.Duration(seconds) * time.Second
}

// resolveReportOutput picks the path to write to: an explicit --output wins,
// then the filename the API suggests for the report it just generated, then a
// name built from the ids. The API's name carries the right extension for the
// format, which the fallback can only guess at.
func resolveReportOutput(output, suggested, fallback string) string {
	switch {
	case output != "":
		return output
	case suggested != "":
		return suggested
	default:
		return fallback
	}
}

func writeReportFile(outputPath string, data []byte) {
	// An empty report is not a report. Writing one and announcing success is
	// what handed CI an unusable file while the exit code said everything was
	// fine — the caller has to know it got nothing.
	if len(data) == 0 {
		logger.Error("The API returned an empty report; %s was left untouched", outputPath)
		os.Exit(1)
	}

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
	reportSBOMCmd.Flags().Int("timeout", 300, "Seconds to wait for the API to finish generating the report")

	// report owasp
	reportOWASPCmd.Flags().String("project-id", "", "Project ID")
	reportOWASPCmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportOWASPCmd.Flags().Bool("detailed", false, "Include detailed information")
	reportOWASPCmd.Flags().String("output", "", "Output file path")
	reportOWASPCmd.Flags().Int("timeout", 300, "Seconds to wait for the API to finish generating the report")

	// report cwe
	reportCWECmd.Flags().String("project-id", "", "Project ID")
	reportCWECmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportCWECmd.Flags().Bool("detailed", false, "Include detailed information")
	reportCWECmd.Flags().String("output", "", "Output file path")
	reportCWECmd.Flags().Int("timeout", 300, "Seconds to wait for the API to finish generating the report")

	// report org
	reportOrgCmd.Flags().String("organization-id", "", "Organization ID (required)")
	reportOrgCmd.Flags().String("type", "owasp", "Report type: owasp, cwe")
	reportOrgCmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportOrgCmd.Flags().Bool("detailed", false, "Include detailed information")
	reportOrgCmd.Flags().String("output", "", "Output file path")
	reportOrgCmd.Flags().Int("timeout", 300, "Seconds to wait for the API to finish generating the report")

	// report team
	reportTeamCmd.Flags().String("team-id", "", "Team ID (required)")
	reportTeamCmd.Flags().String("type", "owasp", "Report type: owasp, cwe")
	reportTeamCmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportTeamCmd.Flags().Bool("detailed", false, "Include detailed information")
	reportTeamCmd.Flags().String("output", "", "Output file path")
	reportTeamCmd.Flags().Int("timeout", 300, "Seconds to wait for the API to finish generating the report")

	// report batch
	reportBatchCmd.Flags().String("organization-id", "", "Organization ID (required)")
	reportBatchCmd.Flags().String("project-ids", "", "Comma-separated project IDs (required)")
	reportBatchCmd.Flags().String("type", "owasp", "Report type: owasp, cwe")
	reportBatchCmd.Flags().String("format", "json", "Output format: json, html, pdf")
	reportBatchCmd.Flags().Bool("detailed", true, "Include detailed information")
	reportBatchCmd.Flags().String("output", "", "Output file path")
	reportBatchCmd.Flags().Int("timeout", 300, "Seconds to wait for the API to finish generating the report")

	// Register subcommands
	reportCmd.AddCommand(reportSBOMCmd)
	reportCmd.AddCommand(reportOWASPCmd)
	reportCmd.AddCommand(reportCWECmd)
	reportCmd.AddCommand(reportOrgCmd)
	reportCmd.AddCommand(reportTeamCmd)
	reportCmd.AddCommand(reportBatchCmd)
}
