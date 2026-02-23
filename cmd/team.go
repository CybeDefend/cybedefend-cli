package cmd

import (
	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/logger"
	"os"

	"github.com/spf13/cobra"
)

// ── Parent command ───────────────────────────────────────────────────

var teamCmd = &cobra.Command{
	Use:   "team",
	Short: "Manage teams",
	Long:  "Create, delete, update, and list CybeDefend teams and their members.",
}

// ── team create ─────────────────────────────────────────────────────

var teamCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new team",
	Run: func(cmd *cobra.Command, args []string) {
		orgID, _ := cmd.Flags().GetString("organization-id")
		name, _ := cmd.Flags().GetString("name")
		desc, _ := cmd.Flags().GetString("description")

		if orgID == "" {
			logger.Error("--organization-id is required")
			os.Exit(1)
		}
		if name == "" {
			logger.Error("--name is required")
			os.Exit(1)
		}
		if desc == "" {
			logger.Error("--description is required")
			os.Exit(1)
		}

		client := newClientFromConfig()
		result, err := client.CreateTeam(orgID, &api.CreateTeamRequest{
			Name:        name,
			Description: desc,
		})
		if err != nil {
			logger.Error("Failed to create team: %v", err)
			os.Exit(1)
		}

		logger.Success("Team created successfully!")
		printJSON(result)
	},
}

// ── team delete ─────────────────────────────────────────────────────

var teamDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a team",
	Run: func(cmd *cobra.Command, args []string) {
		teamID, _ := cmd.Flags().GetString("team-id")
		if teamID == "" {
			logger.Error("--team-id is required")
			os.Exit(1)
		}

		client := newClientFromConfig()
		if err := client.DeleteTeam(teamID); err != nil {
			logger.Error("Failed to delete team: %v", err)
			os.Exit(1)
		}

		logger.Success("Team %s deleted successfully.", teamID)
	},
}

// ── team get ────────────────────────────────────────────────────────

var teamGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Get team details",
	Run: func(cmd *cobra.Command, args []string) {
		orgID, _ := cmd.Flags().GetString("organization-id")
		teamID, _ := cmd.Flags().GetString("team-id")

		if orgID == "" {
			logger.Error("--organization-id is required")
			os.Exit(1)
		}
		if teamID == "" {
			logger.Error("--team-id is required")
			os.Exit(1)
		}

		client := newClientFromConfig()
		team, err := client.GetTeam(orgID, teamID)
		if err != nil {
			logger.Error("Failed to get team: %v", err)
			os.Exit(1)
		}

		printJSON(team)
	},
}

// ── team list ───────────────────────────────────────────────────────

var teamListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all teams in an organization",
	Run: func(cmd *cobra.Command, args []string) {
		orgID, _ := cmd.Flags().GetString("organization-id")
		if orgID == "" {
			logger.Error("--organization-id is required")
			os.Exit(1)
		}

		client := newClientFromConfig()
		teams, err := client.GetAllTeams(orgID)
		if err != nil {
			logger.Error("Failed to list teams: %v", err)
			os.Exit(1)
		}

		if len(teams) == 0 {
			logger.Info("No teams found.")
			return
		}

		printJSON(teams)
	},
}

// ── team update ─────────────────────────────────────────────────────

var teamUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update a team",
	Run: func(cmd *cobra.Command, args []string) {
		teamID, _ := cmd.Flags().GetString("team-id")
		if teamID == "" {
			logger.Error("--team-id is required")
			os.Exit(1)
		}

		reqBody := &api.UpdateTeamRequest{}
		if cmd.Flags().Changed("name") {
			reqBody.Name, _ = cmd.Flags().GetString("name")
		}
		if cmd.Flags().Changed("description") {
			reqBody.Description, _ = cmd.Flags().GetString("description")
		}

		client := newClientFromConfig()
		result, err := client.UpdateTeam(teamID, reqBody)
		if err != nil {
			logger.Error("Failed to update team: %v", err)
			os.Exit(1)
		}

		logger.Success("Team updated successfully!")
		printJSON(result)
	},
}

// ── team members ────────────────────────────────────────────────────

var teamMembersCmd = &cobra.Command{
	Use:   "members",
	Short: "List team members",
	Run: func(cmd *cobra.Command, args []string) {
		teamID, _ := cmd.Flags().GetString("team-id")
		if teamID == "" {
			logger.Error("--team-id is required")
			os.Exit(1)
		}

		page, _ := cmd.Flags().GetInt("page")
		pageSize, _ := cmd.Flags().GetInt("page-size")
		search, _ := cmd.Flags().GetString("search")

		client := newClientFromConfig()
		result, err := client.GetTeamMembers(teamID, page, pageSize, search)
		if err != nil {
			logger.Error("Failed to get team members: %v", err)
			os.Exit(1)
		}

		printJSON(result)
	},
}

// ── team add-member ─────────────────────────────────────────────────

var teamAddMemberCmd = &cobra.Command{
	Use:   "add-member",
	Short: "Add a member to a team",
	Run: func(cmd *cobra.Command, args []string) {
		teamID, _ := cmd.Flags().GetString("team-id")
		userID, _ := cmd.Flags().GetString("user-id")
		role, _ := cmd.Flags().GetString("role")

		if teamID == "" {
			logger.Error("--team-id is required")
			os.Exit(1)
		}
		if userID == "" {
			logger.Error("--user-id is required")
			os.Exit(1)
		}
		if role == "" {
			logger.Error("--role is required (team_manager, analyst_developer, developer, read_only)")
			os.Exit(1)
		}

		client := newClientFromConfig()
		if err := client.AddTeamMember(teamID, &api.AddTeamMemberRequest{
			UserID: userID,
			Role:   role,
		}); err != nil {
			logger.Error("Failed to add member: %v", err)
			os.Exit(1)
		}

		logger.Success("Member added successfully.")
	},
}

// ── team update-member ──────────────────────────────────────────────

var teamUpdateMemberCmd = &cobra.Command{
	Use:   "update-member",
	Short: "Update a team member's role",
	Run: func(cmd *cobra.Command, args []string) {
		teamID, _ := cmd.Flags().GetString("team-id")
		userID, _ := cmd.Flags().GetString("user-id")
		role, _ := cmd.Flags().GetString("role")

		if teamID == "" {
			logger.Error("--team-id is required")
			os.Exit(1)
		}
		if userID == "" {
			logger.Error("--user-id is required")
			os.Exit(1)
		}
		if role == "" {
			logger.Error("--role is required (team_manager, analyst_developer, developer, read_only)")
			os.Exit(1)
		}

		client := newClientFromConfig()
		if err := client.UpdateMemberRole(teamID, &api.UpdateMemberRoleRequest{
			UserID: userID,
			Role:   role,
		}); err != nil {
			logger.Error("Failed to update member role: %v", err)
			os.Exit(1)
		}

		logger.Success("Member role updated successfully.")
	},
}

// ── team remove-member ──────────────────────────────────────────────

var teamRemoveMemberCmd = &cobra.Command{
	Use:   "remove-member",
	Short: "Remove a member from a team",
	Run: func(cmd *cobra.Command, args []string) {
		teamID, _ := cmd.Flags().GetString("team-id")
		userID, _ := cmd.Flags().GetString("user-id")

		if teamID == "" {
			logger.Error("--team-id is required")
			os.Exit(1)
		}
		if userID == "" {
			logger.Error("--user-id is required")
			os.Exit(1)
		}

		client := newClientFromConfig()
		if err := client.RemoveTeamMember(teamID, userID); err != nil {
			logger.Error("Failed to remove member: %v", err)
			os.Exit(1)
		}

		logger.Success("Member removed successfully.")
	},
}

// ── init ────────────────────────────────────────────────────────────

func init() {
	// team create
	teamCreateCmd.Flags().String("organization-id", "", "Organization ID (required)")
	teamCreateCmd.Flags().String("name", "", "Team name (required)")
	teamCreateCmd.Flags().String("description", "", "Team description (required)")

	// team delete
	teamDeleteCmd.Flags().String("team-id", "", "Team ID (required)")

	// team get
	teamGetCmd.Flags().String("organization-id", "", "Organization ID (required)")
	teamGetCmd.Flags().String("team-id", "", "Team ID (required)")

	// team list
	teamListCmd.Flags().String("organization-id", "", "Organization ID (required)")

	// team update
	teamUpdateCmd.Flags().String("team-id", "", "Team ID (required)")
	teamUpdateCmd.Flags().String("name", "", "New team name")
	teamUpdateCmd.Flags().String("description", "", "New team description")

	// team members
	teamMembersCmd.Flags().String("team-id", "", "Team ID (required)")
	teamMembersCmd.Flags().Int("page", 1, "Page number")
	teamMembersCmd.Flags().Int("page-size", 20, "Page size")
	teamMembersCmd.Flags().String("search", "", "Search filter")

	// team add-member
	teamAddMemberCmd.Flags().String("team-id", "", "Team ID (required)")
	teamAddMemberCmd.Flags().String("user-id", "", "User ID (required)")
	teamAddMemberCmd.Flags().String("role", "", "Role: team_manager, analyst_developer, developer, read_only (required)")

	// team update-member
	teamUpdateMemberCmd.Flags().String("team-id", "", "Team ID (required)")
	teamUpdateMemberCmd.Flags().String("user-id", "", "User ID (required)")
	teamUpdateMemberCmd.Flags().String("role", "", "New role: team_manager, analyst_developer, developer, read_only (required)")

	// team remove-member
	teamRemoveMemberCmd.Flags().String("team-id", "", "Team ID (required)")
	teamRemoveMemberCmd.Flags().String("user-id", "", "User ID (required)")

	// Register subcommands
	teamCmd.AddCommand(teamCreateCmd)
	teamCmd.AddCommand(teamDeleteCmd)
	teamCmd.AddCommand(teamGetCmd)
	teamCmd.AddCommand(teamListCmd)
	teamCmd.AddCommand(teamUpdateCmd)
	teamCmd.AddCommand(teamMembersCmd)
	teamCmd.AddCommand(teamAddMemberCmd)
	teamCmd.AddCommand(teamUpdateMemberCmd)
	teamCmd.AddCommand(teamRemoveMemberCmd)
}
