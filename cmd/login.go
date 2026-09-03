// File: cmd/login.go

package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"cybedefend-cli/pkg/auth"
	"cybedefend-cli/pkg/logger"
	"cybedefend-cli/pkg/utils"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

// regionForAuthEndpoint maps a known auth endpoint to its region label.
func regionForAuthEndpoint(authEndpoint string) (string, bool) {
	switch strings.TrimRight(strings.ToLower(strings.TrimSpace(authEndpoint)), "/") {
	case utils.AuthEndpointEu:
		return "eu", true
	case utils.AuthEndpointUs:
		return "us", true
	}
	return "", false
}

// loginCredentials builds the credentials to persist after a successful login.
//
// It captures the endpoints actually used so later commands reuse them verbatim
// instead of re-deriving everything from the region — which silently sent every
// non-production login (self-hosted, on-premise, local) to the prod US region. When the auth
// endpoint matches no known region and no --region was passed, it fails rather
// than defaulting to "us"; the caller must not write anything in that case.
func loginCredentials(authType auth.AuthType, apiURL string, cfg *utils.Config, regionFlag string, regionExplicit bool) (*auth.Credentials, error) {
	region, ok := regionForAuthEndpoint(cfg.AuthEndpoint)
	if !ok {
		if !regionExplicit || strings.TrimSpace(regionFlag) == "" {
			return nil, fmt.Errorf("cannot infer the region from auth endpoint %q. Pass --region explicitly (us or eu)", cfg.AuthEndpoint)
		}
		region = strings.ToLower(strings.TrimSpace(regionFlag))
	}

	return &auth.Credentials{
		Type:         authType,
		Region:       region,
		APIURL:       apiURL,
		AuthEndpoint: cfg.AuthEndpoint,
		ClientID:     cfg.AuthClientID,
		APIResource:  cfg.AuthResource,
	}, nil
}

// currentLoginCredentials builds the credentials for the running `login` command.
func currentLoginCredentials(authType auth.AuthType) (*auth.Credentials, error) {
	return loginCredentials(authType, viper.GetString("api_url"), config, viper.GetString("region"), regionExplicitlySet())
}

// regionExplicitlySet reports whether the user chose a region, as opposed to
// inheriting the "us" default of the --region flag.
func regionExplicitlySet() bool {
	if persistentFlagChanged("region") {
		return true
	}
	if _, set := os.LookupEnv("CYBEDEFEND_REGION"); set {
		return true
	}
	return viper.InConfig("region")
}

// loginWithPAT validates and stores a PAT.
func loginWithPAT(pat string) {
	// Resolved before the token exchange: an unknown endpoint is a config error,
	// no point burning a network round-trip on it.
	creds, err := currentLoginCredentials(auth.AuthTypePAT)
	if err != nil {
		logger.Error("%v", err)
		os.Exit(1)
	}
	creds.PAT = pat

	logger.Info("Validating PAT via token exchange...")

	// Try a token exchange to validate the PAT
	client := newClientFromConfigWithPAT(pat)
	if _, err := client.GetAccessToken(); err != nil {
		logger.Error("PAT validation failed: %v", err)
		os.Exit(1)
	}

	if err := auth.SaveCredentials(creds); err != nil {
		logger.Error("Failed to save credentials: %v", err)
		os.Exit(1)
	}

	logger.Success("Logged in successfully (PAT) on %s. Credentials saved to ~/.cybedefend/credentials.json", creds.APIURL)
}

// loginWithOAuth runs the browser-based OAuth Authorization Code + PKCE flow.
func loginWithOAuth() {
	creds, err := currentLoginCredentials(auth.AuthTypeOAuth)
	if err != nil {
		logger.Error("%v", err)
		os.Exit(1)
	}

	logger.Info("Opening browser for authentication...")

	result, err := auth.RunOAuthFlow(config.AuthEndpoint, config.AuthClientID, config.AuthResource)
	if err != nil {
		logger.Error("OAuth login failed: %v", err)
		os.Exit(1)
	}

	creds.AccessToken = result.AccessToken
	creds.RefreshToken = result.RefreshToken
	creds.TokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)

	if err := auth.SaveCredentials(creds); err != nil {
		logger.Error("Failed to save credentials: %v", err)
		os.Exit(1)
	}

	if result.RefreshToken == "" {
		logger.Warn("No refresh_token received. Make sure 'offline_access' is enabled for the CLI application in the identity provider.")
	}

	logger.Success("Logged in successfully (OAuth). Credentials saved to ~/.cybedefend/credentials.json")
}

func init() {
	// No extra flags needed — login reuses global --pat and --region
}
