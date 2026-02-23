package cmd

import (
	"cybedefend-cli/pkg/logger"
	"os"

	"github.com/spf13/cobra"
)

// ── Parent command ───────────────────────────────────────────────────

var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "View compliance and policy violation data",
	Long:  "Retrieve compliance history, policy violations, and violation statistics for projects.",
}

// ── compliance history ──────────────────────────────────────────────

var complianceHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Get compliance history for a project",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		page, _ := cmd.Flags().GetInt("page")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		startDate, _ := cmd.Flags().GetString("start-date")
		endDate, _ := cmd.Flags().GetString("end-date")

		client := newClientFromConfig()
		result, err := client.GetComplianceHistory(projectID, page, pageSize, startDate, endDate)
		if err != nil {
			logger.Error("Failed to get compliance history: %v", err)
			os.Exit(1)
		}

		printJSON(result)
	},
}

// ── compliance violations ───────────────────────────────────────────

var complianceViolationsCmd = &cobra.Command{
	Use:   "violations",
	Short: "Get policy violations for a project",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		page, _ := cmd.Flags().GetInt("page")
		limit, _ := cmd.Flags().GetInt("limit")

		client := newClientFromConfig()
		result, err := client.GetProjectViolations(projectID, page, limit)
		if err != nil {
			logger.Error("Failed to get violations: %v", err)
			os.Exit(1)
		}

		printJSON(result)
	},
}

// ── compliance stats ────────────────────────────────────────────────

var complianceStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Get violation statistics for a project",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		startDate, _ := cmd.Flags().GetString("start-date")
		endDate, _ := cmd.Flags().GetString("end-date")

		client := newClientFromConfig()
		result, err := client.GetViolationStats(projectID, startDate, endDate)
		if err != nil {
			logger.Error("Failed to get violation stats: %v", err)
			os.Exit(1)
		}

		printJSON(result)
	},
}

// ── init ────────────────────────────────────────────────────────────

func init() {
	// compliance history
	complianceHistoryCmd.Flags().String("project-id", "", "Project ID")
	complianceHistoryCmd.Flags().Int("page", 1, "Page number")
	complianceHistoryCmd.Flags().Int("page-size", 20, "Items per page")
	complianceHistoryCmd.Flags().String("start-date", "", "Start date (ISO format)")
	complianceHistoryCmd.Flags().String("end-date", "", "End date (ISO format)")

	// compliance violations
	complianceViolationsCmd.Flags().String("project-id", "", "Project ID")
	complianceViolationsCmd.Flags().Int("page", 1, "Page number")
	complianceViolationsCmd.Flags().Int("limit", 20, "Items per page")

	// compliance stats
	complianceStatsCmd.Flags().String("project-id", "", "Project ID")
	complianceStatsCmd.Flags().String("start-date", "", "Start date (ISO format)")
	complianceStatsCmd.Flags().String("end-date", "", "End date (ISO format)")

	// Register subcommands
	complianceCmd.AddCommand(complianceHistoryCmd)
	complianceCmd.AddCommand(complianceViolationsCmd)
	complianceCmd.AddCommand(complianceStatsCmd)
}
