// File: pkg/utils/config.go

package utils

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	APIURL    string
	APIKey    string
	ProjectID string
	CI        bool
	DEBUG     bool
}

func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")            // Name of config file (without extension)
	viper.SetConfigType("yaml")              // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")                 // Look for config in the current directory
	viper.AddConfigPath("$HOME/.cybedefend") // Optionally look for config in the user's home directory
	viper.AddConfigPath("/etc/cybedefend/")  // Optionally look for config in /etc/cybedefend/

	// Set default values
	viper.SetDefault("api_url", "https://api-preprod.cybedefend.com")
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

	config := &Config{
		APIURL:    viper.GetString("api_url"),
		APIKey:    viper.GetString("api_key"),
		ProjectID: viper.GetString("project_id"),
		CI:        viper.GetBool("ci"),
		DEBUG:     viper.GetBool("debug"),
	}

	return config, nil
}
