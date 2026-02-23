// File: cmd/login.go

package cmd

import (
	"os"
	"time"

	"cybedefend-cli/pkg/auth"
	"cybedefend-cli/pkg/logger"

	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with CybeDefend",
	Long: `Authenticate with CybeDefend and store credentials locally.

Two modes are supported:

  Interactive (OAuth — default):
    cybedefend login --region eu
    Opens a browser for secure OAuth login. Not available in CI mode.

  PAT (Personal Access Token):
    cybedefend login --pat YOUR_PAT --region eu
    Stores the PAT for future commands. Required in CI mode.

Credentials are saved to ~/.cybedefend/credentials.json.
Once logged in, you no longer need to pass --pat on every command.`,
	Run: func(cmd *cobra.Command, args []string) {
		pat, _ := cmd.Flags().GetString("pat")
		ci := config.CI

		if ci && pat == "" {
			logger.Error("In CI mode, --pat is required. OAuth browser login is not available in CI.")
			os.Exit(1)
		}

		if pat != "" {
			loginWithPAT(pat)
		} else {
			loginWithOAuth()
		}
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored CybeDefend credentials",
	Run: func(cmd *cobra.Command, args []string) {
		if err := auth.DeleteCredentials(); err != nil {
			logger.Error("Failed to remove credentials: %v", err)
			os.Exit(1)
		}
		logger.Success("Logged out — credentials removed.")
	},
}

// loginWithPAT validates and stores a PAT.
func loginWithPAT(pat string) {
	logger.Info("Validating PAT via token exchange...")

	// Try a token exchange to validate the PAT
	client := newClientFromConfigWithPAT(pat)
	_, err := client.GetAccessToken()
	if err != nil {
		logger.Error("PAT validation failed: %v", err)
		os.Exit(1)
	}

	region := "us"
	if config.AuthEndpoint == "https://auth-eu.cybedefend.com" {
		region = "eu"
	}

	creds := &auth.Credentials{
		Type:   auth.AuthTypePAT,
		Region: region,
		PAT:    pat,
	}
	if err := auth.SaveCredentials(creds); err != nil {
		logger.Error("Failed to save credentials: %v", err)
		os.Exit(1)
	}

	logger.Success("Logged in successfully (PAT). Credentials saved to ~/.cybedefend/credentials.json")
}

// loginWithOAuth runs the browser-based OAuth Authorization Code + PKCE flow.
func loginWithOAuth() {
	logger.Info("Opening browser for authentication...")

	result, err := auth.RunOAuthFlow(config.AuthEndpoint, config.LogtoClientID, config.LogtoAPIResource)
	if err != nil {
		logger.Error("OAuth login failed: %v", err)
		os.Exit(1)
	}

	region := "us"
	if config.AuthEndpoint == "https://auth-eu.cybedefend.com" {
		region = "eu"
	}

	expiry := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)

	creds := &auth.Credentials{
		Type:         auth.AuthTypeOAuth,
		Region:       region,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		TokenExpiry:  expiry,
	}
	if err := auth.SaveCredentials(creds); err != nil {
		logger.Error("Failed to save credentials: %v", err)
		os.Exit(1)
	}

	if result.RefreshToken == "" {
		logger.Warn("No refresh_token received. Make sure 'offline_access' is enabled for the CLI application in Logto admin.")
	}

	logger.Success("Logged in successfully (OAuth). Credentials saved to ~/.cybedefend/credentials.json")
}

func init() {
	// No extra flags needed — login reuses global --pat and --region
}
