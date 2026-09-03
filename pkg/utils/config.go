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

	// Fallback CLI application client IDs (used when /client-apps is unreachable).
	AuthClientIDUs = "7o6r9cvvi8um0kisvn7hm"
	AuthClientIDEu = "fm90ay05zohu8fk2q45ms"
)

// FetchClientApp reads the /client-apps document of a CybeDefend instance and
// returns the CLI application id and the token resource that instance mints
// tokens for.
//
// Both values belong to the instance that served them. Presenting one
// deployment's client id, or one deployment's resource, to another deployment's
// auth server is what produces the opaque invalid_grant — which is why they are
// read together, from the API actually being called, rather than derived from
// the region.
//
// ok is false when the instance cannot be reached or advertises no CLI
// application; the caller then falls back to its own defaults.
func FetchClientApp(apiURL string) (clientID, resource string, ok bool) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(apiURL + "/client-apps")
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", false
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", false
	}
	var result struct {
		CLI struct {
			AppID string `json:"appId"`
		} `json:"cli"`
		// Field name chosen by the API, not by us.
		Resource string `json:"logtoResource"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.CLI.AppID == "" {
		return "", "", false
	}
	return result.CLI.AppID, result.Resource, true
}

// FetchCLIClientID retrieves the CLI application client ID from the API.
// Falls back to the hardcoded constant if the endpoint is unreachable.
func FetchCLIClientID(apiURL, fallback string) string {
	if clientID, _, ok := FetchClientApp(apiURL); ok {
		return clientID
	}
	return fallback
}

type Config struct {
	APIURL       string
	PAT          string
	AuthEndpoint string
	AuthClientID string
	AuthResource string // always the real registered API resource (never localhost)
	ProjectID    string
	Branch       string
	CI           bool
	DEBUG        bool
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

	// The auth endpoint is the one value the region can speak for.
	var authEndpoint, fallbackClientID string
	switch viper.GetString("region") {
	case "eu":
		authEndpoint, fallbackClientID = AuthEndpointEu, AuthClientIDEu
	default:
		authEndpoint, fallbackClientID = AuthEndpointUs, AuthClientIDUs
	}
	// A deployment that is not one of the two regions has no region to derive an
	// auth server from, and /client-apps does not advertise one, so an explicit
	// auth_endpoint stays the only way to name it.
	if override := viper.GetString("auth_endpoint"); override != "" {
		authEndpoint = override
	}

	apiURL := viper.GetString("api_url")

	// The resource is the audience of the token, so it is the API being called,
	// never the region's, and the client id belongs to that same instance. When
	// either was derived from the region, a deployment reached through an
	// explicit api_url received the production identity and rejected the
	// exchange as invalid_grant.
	authResource := apiURL
	authClientID, discovered, ok := FetchClientApp(apiURL)
	if !ok {
		authClientID = fallbackClientID
	} else if discovered != "" {
		// An instance that names its own resource wins over the URL it was
		// inferred from.
		authResource = discovered
	}

	config := &Config{
		APIURL:       apiURL,
		PAT:          viper.GetString("pat"),
		AuthEndpoint: authEndpoint,
		AuthClientID: authClientID,
		AuthResource: authResource,
		ProjectID:    viper.GetString("project_id"),
		Branch:       viper.GetString("branch"),
		CI:           viper.GetBool("ci"),
		DEBUG:        viper.GetBool("debug"),
	}

	return config, nil
}
