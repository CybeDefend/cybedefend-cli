package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/validation"
	"os"

	"github.com/spf13/cobra"
)

// ── Parent command ───────────────────────────────────────────────────

var overviewCmd = &cobra.Command{
	Use:   "overview",
	Short: "Get security overviews",
	Long:  "Retrieve security overview dashboards for projects or organizations.",
}

// ── overview project ────────────────────────────────────────────────

var overviewProjectCmd = &cobra.Command{
	Use:   "project",
	Short: "Get project security overview",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		branchesStr, _ := cmd.Flags().GetString("branches")
		branches := splitCSV(branchesStr)

		if err := validation.Struct(validation.OverviewInput{
			ProjectID: projectID,
			Branches:  branches,
		}); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}

		client := newClientFromConfig()
		overview, err := client.GetProjectOverview(projectID, branches)
		if err != nil {
			logger.Error("Failed to get project overview: %v", err)
			os.Exit(1)
		}

		printJSON(overview)
	},
}

// ── overview org ────────────────────────────────────────────────────

var overviewOrgCmd = &cobra.Command{
	Use:   "org",
	Short: "Get organization security overview",
	Run: func(cmd *cobra.Command, args []string) {
		orgID, _ := cmd.Flags().GetString("organization-id")
		severityFilter, _ := cmd.Flags().GetString("severity-filter")
		statusFilter, _ := cmd.Flags().GetString("status-filter")
		analysisTypes, _ := cmd.Flags().GetString("analysis-types")
		dateFrom, _ := cmd.Flags().GetString("date-from")
		dateTo, _ := cmd.Flags().GetString("date-to")
		branchesStr, _ := cmd.Flags().GetString("branches")
		teamIDsStr, _ := cmd.Flags().GetString("team-ids")
		trendPeriodDays, _ := cmd.Flags().GetInt("trend-period-days")

		branches := splitCSV(branchesStr)
		teamIDs := splitCSV(teamIDsStr)

		requireID("--organization-id", orgID)
		if err := validation.Struct(validation.OverviewInput{
			OrganizationID:  orgID,
			TeamIDs:         teamIDs,
			Branches:        branches,
			DateFrom:        dateFrom,
			DateTo:          dateTo,
			TrendPeriodDays: trendPeriodDays,
		}); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}

		params := &api.OrgOverviewParams{
			DateFrom:        dateFrom,
			DateTo:          dateTo,
			Branches:        branches,
			TeamIDs:         teamIDs,
			TrendPeriodDays: trendPeriodDays,
		}
		// The API owns the vocabulary of these three filters, so they are passed
		// through as given rather than checked against a list the CLI would have
		// to keep in step.
		params.SeverityFilter = splitCSV(severityFilter)
		params.StatusFilter = splitCSV(statusFilter)
		params.AnalysisTypes = splitCSV(analysisTypes)

		client := newClientFromConfig()
		overview, err := client.GetOrgOverview(orgID, params)
		if err != nil {
			logger.Error("Failed to get organization overview: %v", err)
			os.Exit(1)
		}

		printJSON(overview)
	},
}

// ── init ────────────────────────────────────────────────────────────

func init() {
	// overview project
	overviewProjectCmd.Flags().String("project-id", "", "Project ID")
	overviewProjectCmd.Flags().String("branches", "", "Comma-separated branch names")

	// overview org
	overviewOrgCmd.Flags().String("organization-id", "", "Organization ID (required)")
	overviewOrgCmd.Flags().String("severity-filter", "", "Comma-separated severity filters")
	overviewOrgCmd.Flags().String("status-filter", "", "Comma-separated status filters")
	overviewOrgCmd.Flags().String("analysis-types", "", "Comma-separated analysis types")
	overviewOrgCmd.Flags().String("date-from", "", "Start date (ISO format)")
	overviewOrgCmd.Flags().String("date-to", "", "End date (ISO format)")
	overviewOrgCmd.Flags().String("branches", "", "Comma-separated branch names")
	overviewOrgCmd.Flags().String("team-ids", "", "Comma-separated team IDs")
	overviewOrgCmd.Flags().Int("trend-period-days", 0, "Trend period in days")

	overviewCmd.AddCommand(overviewProjectCmd)
	overviewCmd.AddCommand(overviewOrgCmd)
}
