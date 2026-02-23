package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/auth"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/utils"
	"encoding/json"
	"fmt"
	"os"
	"time"

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

		if teamID == "" {
			logger.Error("--team-id is required")
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

// newClientFromConfig creates an API client using the current viper/config state.
// Priority: 1) --pat flag / env / config  2) stored credentials from `cybedefend login`
func newClientFromConfig() *api.Client {
	pat := viper.GetString("pat")
	apiURL := viper.GetString("api_url")

	// If PAT is provided explicitly, use PAT mode (honour current --region / config).
	if pat != "" {
		return api.NewClient(apiURL, pat, config.AuthEndpoint, config.LogtoClientID, config.LogtoAPIResource)
	}

	// Try to load stored credentials.
	creds, err := auth.LoadCredentials()
	if err == nil && creds != nil {
		// Derive endpoints from the region stored in credentials, not the CLI default.
		credAPIURL, credAuthEndpoint, credClientID, credAPIResource := regionEndpoints(creds.Region)

		switch creds.Type {
		case auth.AuthTypePAT:
			return api.NewClient(credAPIURL, creds.PAT, credAuthEndpoint, credClientID, credAPIResource)
		case auth.AuthTypeOAuth:
			expiry, _ := time.Parse(time.RFC3339, creds.TokenExpiry)
			return api.NewClientWithOAuth(credAPIURL, credAuthEndpoint, credClientID, credAPIResource,
				creds.AccessToken, creds.RefreshToken, expiry, creds.Region)
		}
	}

	// No credentials found — return client anyway; it will error on first API call.
	return api.NewClient(apiURL, "", config.AuthEndpoint, config.LogtoClientID, config.LogtoAPIResource)
}

// regionEndpoints returns the API URL, auth endpoint, Logto client ID and API resource
// for a given region string ("eu" or anything else → us).
func regionEndpoints(region string) (apiURL, authEndpoint, clientID, apiResource string) {
	if region == "eu" {
		return utils.APIURLEu, utils.AuthEndpointEu, utils.FetchCLIClientID(utils.APIURLEu, utils.LogtoClientIDEu), utils.APIURLEu
	}
	return utils.APIURLUs, utils.AuthEndpointUs, utils.FetchCLIClientID(utils.APIURLUs, utils.LogtoClientIDUs), utils.APIURLUs
}

// newClientFromConfigWithPAT creates an API client using an explicit PAT (used by login --pat).
func newClientFromConfigWithPAT(pat string) *api.Client {
	apiURL := viper.GetString("api_url")
	return api.NewClient(apiURL, pat, config.AuthEndpoint, config.LogtoClientID, config.LogtoAPIResource)
}

// getProjectID reads --project-id from flag, env, or config.
func getProjectID(cmd *cobra.Command) string {
	pid, _ := cmd.Flags().GetString("project-id")
	if pid == "" {
		pid = viper.GetString("project_id")
	}
	if pid == "" {
		logger.Error("--project-id is required")
		os.Exit(1)
	}
	return pid
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
