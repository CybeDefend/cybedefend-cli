package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/validation"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ── Parent command ───────────────────────────────────────────────────

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Manage projects",
	Long:  "Create, delete, and retrieve CybeDefend projects.",
}

// ── project create ──────────────────────────────────────────────────

var projectCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new project",
	Run: func(cmd *cobra.Command, args []string) {
		teamID, _ := cmd.Flags().GetString("team-id")
		name, _ := cmd.Flags().GetString("name")

		// The team id is interpolated into the create-project URL path.
		if err := validation.ResourceID("--team-id", teamID); err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
		if name == "" {
			logger.Error("--name is required")
			os.Exit(1)
		}

		client := newClientFromConfig()

		reqBody := &api.CreateProjectRequest{Name: name}

		if cmd.Flags().Changed("ai-merge-request") {
			v, _ := cmd.Flags().GetBool("ai-merge-request")
			reqBody.AIMergeRequestEnabled = &v
		}
		if cmd.Flags().Changed("improving-results") {
			v, _ := cmd.Flags().GetBool("improving-results")
			reqBody.ImprovingResultsEnabled = &v
		}
		if cmd.Flags().Changed("auto-fix") {
			v, _ := cmd.Flags().GetBool("auto-fix")
			reqBody.AutoFixEnabled = &v
		}

		project, err := client.CreateProject(teamID, reqBody)
		if err != nil {
			logger.Error("Failed to create project: %v", err)
			os.Exit(1)
		}

		logger.Success("Project created successfully!")
		printJSON(project)
	},
}

// ── project delete ──────────────────────────────────────────────────

var projectDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a project",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		client := newClientFromConfig()

		if err := client.DeleteProject(projectID); err != nil {
			logger.Error("Failed to delete project: %v", err)
			os.Exit(1)
		}

		logger.Success("Project %s deleted successfully.", projectID)
	},
}

// ── project get ─────────────────────────────────────────────────────

var projectGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get project details",
	Run: func(cmd *cobra.Command, args []string) {
		projectID := getProjectID(cmd)
		client := newClientFromConfig()

		project, err := client.GetProject(projectID)
		if err != nil {
			logger.Error("Failed to get project: %v", err)
			os.Exit(1)
		}

		printJSON(project)
	},
}

// ── helpers ─────────────────────────────────────────────────────────

// getProjectID reads --project-id from flag, env, or config.
func getProjectID(cmd *cobra.Command) string {
	pid, _ := cmd.Flags().GetString("project-id")
	if pid == "" {
		pid = viper.GetString("project_id")
	}
	// Every caller hands this id straight to a client method that interpolates
	// it into an API URL path, so it is checked once here rather than in each
	// of the report, compliance, container and overview commands.
	if err := validation.ResourceID("--project-id", pid); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
	return pid
}

// requireID asserts an id a subcommand cannot run without, and that it is safe
// to interpolate into an API URL path.
func requireID(flag, value string) {
	if err := validation.ResourceID(flag, value); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

// splitCSV splits a comma-separated flag into its values, dropping the empty
// entries a hand-typed list leaves behind: "a, b" and a trailing comma both
// used to reach the API as values in their own right.
func splitCSV(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			values = append(values, item)
		}
	}
	return values
}

// printJSON marshals v to indented JSON and prints to stdout.
func printJSON(v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		logger.Error("Error formatting output: %v", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

// ── init ────────────────────────────────────────────────────────────

func init() {
	// project create flags
	projectCreateCmd.Flags().String("team-id", "", "Team ID (required)")
	projectCreateCmd.Flags().String("name", "", "Project name (required)")
	projectCreateCmd.Flags().Bool("ai-merge-request", false, "Enable AI merge request")
	projectCreateCmd.Flags().Bool("improving-results", false, "Enable improving results")
	projectCreateCmd.Flags().Bool("auto-fix", false, "Enable auto fix")

	// project delete flags
	projectDeleteCmd.Flags().String("project-id", "", "Project ID (required)")

	// project get flags
	projectGetCmd.Flags().String("project-id", "", "Project ID")

	// Register subcommands
	projectCmd.AddCommand(projectCreateCmd)
	projectCmd.AddCommand(projectDeleteCmd)
	projectCmd.AddCommand(projectGetCmd)
}
