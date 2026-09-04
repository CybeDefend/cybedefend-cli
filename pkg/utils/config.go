// File: pkg/utils/config.go

package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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
// The error says why discovery failed — a status code or a transport error —
// because the caller has to put it in front of the user: for a deployment that
// is not one of the two regions there is no identity to fall back to.
func FetchClientApp(apiURL string) (clientID, resource string, err error) {
	for attempt := 1; ; attempt++ {
		clientID, resource, err = fetchClientAppOnce(apiURL)
		// A refusal is an answer: retrying a 4xx only delays a failure the user
		// has to act on. A transport error or a 5xx is worth another try.
		if err == nil || attempt == clientAppAttempts || !worthRetrying(err) {
			return clientID, resource, err
		}
		time.Sleep(time.Duration(attempt) * clientAppRetryDelay)
	}
}

const (
	// Discovery gates the whole command, and the traffic may cross a VPN, an
	// exit node or a proxy where several seconds for one request is normal.
	clientAppTimeout    = 15 * time.Second
	clientAppAttempts   = 3
	clientAppRetryDelay = 500 * time.Millisecond
)

// retryableError marks the failures that another attempt could resolve.
type retryableError struct{ error }

func worthRetrying(err error) bool {
	var r retryableError
	return errors.As(err, &r)
}

func fetchClientAppOnce(apiURL string) (clientID, resource string, err error) {
	client := &http.Client{Timeout: clientAppTimeout}
	url := strings.TrimRight(apiURL, "/") + "/client-apps"

	resp, err := client.Get(url)
	if err != nil {
		// The instance was never reached: a timeout, a reset, a DNS hiccup.
		return "", "", retryableError{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		statusErr := fmt.Errorf("HTTP %d", resp.StatusCode)
		if resp.StatusCode >= 500 {
			return "", "", retryableError{statusErr}
		}
		return "", "", statusErr
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}
	var result struct {
		CLI struct {
			AppID string `json:"appId"`
		} `json:"cli"`
		// Field name chosen by the API, not by us.
		Resource string `json:"logtoResource"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("unreadable response: %w", err)
	}
	if result.CLI.AppID == "" {
		return "", "", fmt.Errorf("the response names no CLI application")
	}
	return result.CLI.AppID, result.Resource, nil
}

// regionFallbackFor returns the built-in client application of a region's API
// URL, so a momentary failure to reach /client-apps on the cloud does not stop
// a scan.
//
// ok is false for every other URL, and deliberately so: these applications are
// registered with the cloud and are unknown to any other deployment. Sending
// one anyway reports `invalid_client` naming an id the user never configured,
// which points at the wrong thing entirely.
func regionFallbackFor(apiURL string) (clientID string, ok bool) {
	switch strings.TrimRight(strings.ToLower(strings.TrimSpace(apiURL)), "/") {
	case APIURLUs:
		return AuthClientIDUs, true
	case APIURLEu:
		return AuthClientIDEu, true
	}
	return "", false
}

// FetchCLIClientID retrieves the CLI application client ID from the API.
// Falls back to the hardcoded constant if the endpoint is unreachable.
func FetchCLIClientID(apiURL, fallback string) string {
	if clientID, _, err := FetchClientApp(apiURL); err == nil {
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
	var authEndpoint string
	switch viper.GetString("region") {
	case "eu":
		authEndpoint = AuthEndpointEu
	default:
		authEndpoint = AuthEndpointUs
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
	authClientID, discovered, discoveryErr := FetchClientApp(apiURL)
	switch {
	case discoveryErr == nil:
		// An instance that names its own resource wins over the URL it was
		// inferred from.
		if discovered != "" {
			authResource = discovered
		}
	default:
		// Only a region has an identity worth assuming when discovery fails.
		fallback, ok := regionFallbackFor(apiURL)
		if !ok {
			return nil, fmt.Errorf("cannot discover the client application from %s/client-apps: %w\n"+
				"That is the CybeDefend instance named by api_url. Check that it is reachable from where the CLI "+
				"runs — a CI runner does not necessarily have the same access as a workstation",
				strings.TrimRight(apiURL, "/"), discoveryErr)
		}
		authClientID = fallback
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
