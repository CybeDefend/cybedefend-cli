// File: pkg/utils/config.go

package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/spf13/viper"
)

// API URL constants
const (
	APIURLUs = "https://api-us.cybedefend.com"
	APIURLEu = "https://api-eu.cybedefend.com"
)

// Auth endpoint constants (per region)
const (
	AuthEndpointUs = "https://auth-us.cybedefend.com"
	AuthEndpointEu = "https://auth-eu.cybedefend.com"

	// Fallback Logto application client IDs (used when /client-apps is unreachable).
	LogtoClientIDUs = "7o6r9cvvi8um0kisvn7hm"
	LogtoClientIDEu = "fm90ay05zohu8fk2q45ms"
)

// FetchCLIClientID retrieves the CLI application client ID from the API.
// Falls back to the hardcoded constant if the endpoint is unreachable.
func FetchCLIClientID(apiURL, fallback string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(apiURL + "/client-apps")
	if err != nil {
		return fallback
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fallback
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fallback
	}
	var result struct {
		CLI struct {
			AppID string `json:"appId"`
		} `json:"cli"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.CLI.AppID == "" {
		return fallback
	}
	return result.CLI.AppID
}

type Config struct {
	APIURL           string
	PAT              string
	AuthEndpoint     string
	LogtoClientID    string
	LogtoAPIResource string // always the real registered API resource (never localhost)
	ProjectID        string
	Branch           string
	CI               bool
	DEBUG            bool
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")            // Name of config file (without extension)
	viper.SetConfigType("yaml")              // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")                 // Look for config in the current directory
	viper.AddConfigPath("$HOME/.cybedefend") // Optionally look for config in the user's home directory
	viper.AddConfigPath("/etc/cybedefend/")  // Optionally look for config in /etc/cybedefend/

	// Set default values
	viper.SetDefault("api_url", APIURLUs)
	viper.SetDefault("ci", false) // Default CI to false

	// Read in environment variables that match
	viper.SetEnvPrefix("CYBEDEFEND")
	viper.AutomaticEnv()

	// Read the config file if it exists
	err := viper.ReadInConfig()
	if err != nil {
		// Config file not found; ignore error if desired
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Derive region-aware auth endpoint, client ID and API resource from region (hardcoded, not overridable)
	var authEndpoint, logtoClientID, logtoAPIResource string
	r := viper.GetString("region")
	switch r {
	case "eu":
		authEndpoint = AuthEndpointEu
		logtoClientID = FetchCLIClientID(APIURLEu, LogtoClientIDEu)
		logtoAPIResource = APIURLEu
	default:
		authEndpoint = AuthEndpointUs
		logtoClientID = FetchCLIClientID(APIURLUs, LogtoClientIDUs)
		logtoAPIResource = APIURLUs
	}
	// Allow explicit auth_endpoint override (e.g. self-hosted)
	if override := viper.GetString("auth_endpoint"); override != "" {
		authEndpoint = override
	}

	config := &Config{
		APIURL:           viper.GetString("api_url"),
		PAT:              viper.GetString("pat"),
		AuthEndpoint:     authEndpoint,
		LogtoClientID:    logtoClientID,
		LogtoAPIResource: logtoAPIResource,
		ProjectID:        viper.GetString("project_id"),
		Branch:           viper.GetString("branch"),
		CI:               viper.GetBool("ci"),
		DEBUG:            viper.GetBool("debug"),
	}

	return config, nil
}
