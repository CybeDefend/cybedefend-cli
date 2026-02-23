// File: pkg/utils/config.go

package utils

import (
	"fmt"

	"github.com/spf13/viper"
)

// API URL constants
const (
	APIURLUs = "https://api-us.cybedefend.com"
	APIURLEu = "https://api-eu.cybedefend.com"
)

// Logto endpoint constants (per region)
const (
	LogtoEndpointUs = "https://auth-us.cybedefend.com"
	LogtoEndpointEu = "https://auth-eu.cybedefend.com"

	// DefaultLogtoClientID is the Logto application client ID for the CybeDefend CLI.
	// Override via --logto-client-id flag or logto_client_id in config.
	DefaultLogtoClientID = "cybedefend-cli"
)

type Config struct {
	APIURL         string
	PAT            string
	LogtoEndpoint  string
	LogtoClientID  string
	ProjectID      string
	Branch         string
	CI             bool
	DEBUG          bool
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
	viper.SetDefault("logto_client_id", DefaultLogtoClientID)

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

	// Derive region-aware Logto endpoint if not explicitly configured
	logtoEndpoint := viper.GetString("logto_endpoint")
	if logtoEndpoint == "" {
		r := viper.GetString("region")
		switch r {
		case "eu":
			logtoEndpoint = LogtoEndpointEu
		default:
			logtoEndpoint = LogtoEndpointUs
		}
	}

	config := &Config{
		APIURL:        viper.GetString("api_url"),
		PAT:           viper.GetString("pat"),
		LogtoEndpoint: logtoEndpoint,
		LogtoClientID: viper.GetString("logto_client_id"),
		ProjectID:     viper.GetString("project_id"),
		Branch:        viper.GetString("branch"),
		CI:            viper.GetBool("ci"),
		DEBUG:         viper.GetBool("debug"),
	}

	return config, nil
}
