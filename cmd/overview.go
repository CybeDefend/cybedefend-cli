package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"os"
	"strings"

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

		var branches []string
		if branchesStr != "" {
			branches = strings.Split(branchesStr, ",")
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
		if orgID == "" {
			logger.Error("--organization-id is required")
			os.Exit(1)
		}

		params := &api.OrgOverviewParams{}

		if v, _ := cmd.Flags().GetString("severity-filter"); v != "" {
			params.SeverityFilter = strings.Split(v, ",")
		}
		if v, _ := cmd.Flags().GetString("status-filter"); v != "" {
			params.StatusFilter = strings.Split(v, ",")
		}
		if v, _ := cmd.Flags().GetString("analysis-types"); v != "" {
			params.AnalysisTypes = strings.Split(v, ",")
		}
		if v, _ := cmd.Flags().GetString("date-from"); v != "" {
			params.DateFrom = v
		}
		if v, _ := cmd.Flags().GetString("date-to"); v != "" {
			params.DateTo = v
		}
		if v, _ := cmd.Flags().GetString("branches"); v != "" {
			params.Branches = strings.Split(v, ",")
		}
		if v, _ := cmd.Flags().GetString("team-ids"); v != "" {
			params.TeamIDs = strings.Split(v, ",")
		}
		if v, _ := cmd.Flags().GetInt("trend-period-days"); v > 0 {
			params.TrendPeriodDays = v
		}

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
