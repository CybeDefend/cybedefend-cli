// File: pkg/utils/config.go

package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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

// SensitiveConfigKeys are the configuration keys that decide *where* the user's
// credentials and source code are sent: the PAT itself, the endpoint the raw PAT
// is exchanged at, and the API base URL that receives the resulting Bearer token
// and the uploaded source tree.
//
// The CLI's primary use case is `cybedefend scan --dir .` from the root of the
// repository being scanned (CI, forks, pull requests), and viper discovers
// ./config.yml from that working directory. A checked-in config.yml is therefore
// attacker-authored, and these keys are only honoured from a trusted config
// file. Everything else (project_id, branch, region, app_url, ci, debug…) stays
// readable from a repo-local config file — that is its legitimate purpose.
var SensitiveConfigKeys = []string{"api_url", "auth_endpoint", "pat"}

// TrustedConfigDirs returns the directories a config file may supply
// SensitiveConfigKeys from.
func TrustedConfigDirs() []string {
	dirs := []string{filepath.Clean("/etc/cybedefend")}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, ".cybedefend"))
	}
	return dirs
}

// IsTrustedConfigFile reports whether configFile may supply SensitiveConfigKeys.
//
//   - an empty configFile means no config file was loaded: nothing to distrust.
//   - a file the operator named themselves with --config is trusted.
//   - a file sitting directly in one of trustedDirs is trusted.
//   - anything else — in particular ./config.yml picked up from the working
//     directory — is not.
func IsTrustedConfigFile(configFile, explicitConfigFile string, trustedDirs []string) bool {
	if configFile == "" {
		return true
	}

	used := absClean(configFile)
	if explicitConfigFile != "" && samePath(explicitConfigFile, used) {
		return true
	}

	dir := filepath.Dir(used)
	for _, trusted := range trustedDirs {
		if samePath(trusted, dir) {
			return true
		}
	}
	return false
}

// samePath reports whether a and b designate the same location. Cleaned absolute
// paths are compared first; when both exist on disk os.SameFile settles the
// symlinked cases (/var vs /private/var on macOS, a symlinked $HOME, …) so that
// a legitimate config file is never mistaken for an untrusted one.
func samePath(a, b string) bool {
	absA, absB := absClean(a), absClean(b)
	if absA == absB {
		return true
	}
	infoA, err := os.Stat(absA)
	if err != nil {
		return false
	}
	infoB, err := os.Stat(absB)
	if err != nil {
		return false
	}
	return os.SameFile(infoA, infoB)
}

// EnforceConfigTrustBoundary blanks the SensitiveConfigKeys carried by an
// untrusted config file. It reports whether the loaded config file is trusted
// and which keys were neutralized.
//
// The values are blanked *in the config layer* rather than overridden, so
// viper's normal precedence still applies: a --pat flag or a CYBEDEFEND_PAT
// environment variable — both trusted, operator-supplied sources — keep winning,
// and only the file's contribution disappears. Blanking an already blank value
// is a no-op, so the function is idempotent and safe to call more than once.
func EnforceConfigTrustBoundary(v *viper.Viper, explicitConfigFile string) (trusted bool, neutralized []string) {
	if v == nil {
		return true, nil
	}
	if IsTrustedConfigFile(v.ConfigFileUsed(), explicitConfigFile, TrustedConfigDirs()) {
		return true, nil
	}

	blank := make(map[string]any, len(SensitiveConfigKeys))
	for _, key := range SensitiveConfigKeys {
		if !v.InConfig(key) {
			continue
		}
		blank[key] = ""
		neutralized = append(neutralized, key)
	}
	if len(blank) > 0 {
		// MergeConfigMap only ever fails on a nil receiver, which is excluded above.
		_ = v.MergeConfigMap(blank)
	}
	return false, neutralized
}

func absClean(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
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

// LoadConfig assembles the effective configuration.
//
// explicitConfigFile is the path the operator passed with --config (empty when
// unset). It is what tells a config file the user deliberately pointed at apart
// from one merely discovered in the working directory; only the former may carry
// SensitiveConfigKeys. See EnforceConfigTrustBoundary.
func LoadConfig(explicitConfigFile string) (*Config, error) {
	viper.SetConfigName("config") // Name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	// The working directory is the repository being scanned in the CLI's main
	// use case, so a config.yml found here is untrusted input: it may still
	// carry project settings (project_id, branch, …) but never api_url,
	// auth_endpoint or pat — EnforceConfigTrustBoundary strips those below.
	viper.AddConfigPath(".")                 // Look for config in the current directory
	viper.AddConfigPath("$HOME/.cybedefend") // Optionally look for config in the user's home directory
	viper.AddConfigPath("/etc/cybedefend/")  // Optionally look for config in /etc/cybedefend/

	// Must come last: viper.SetConfigName clears any previously set config file.
	if explicitConfigFile != "" {
		viper.SetConfigFile(explicitConfigFile)
	}

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

	// Must run after every ReadInConfig: reading repopulates the config layer
	// straight from the file on disk. Idempotent, so the root command applying
	// it earlier (to decide whether api_url is region-derived) is not undone.
	EnforceConfigTrustBoundary(viper.GetViper(), explicitConfigFile)

	// Derive region-aware auth endpoint, client ID and API resource from region (hardcoded, not overridable)
	var authEndpoint, logtoClientID, logtoAPIResource, defaultAPIURL string
	r := viper.GetString("region")
	switch r {
	case "eu":
		authEndpoint = AuthEndpointEu
		logtoClientID = FetchCLIClientID(APIURLEu, LogtoClientIDEu)
		logtoAPIResource = APIURLEu
		defaultAPIURL = APIURLEu
	default:
		authEndpoint = AuthEndpointUs
		logtoClientID = FetchCLIClientID(APIURLUs, LogtoClientIDUs)
		logtoAPIResource = APIURLUs
		defaultAPIURL = APIURLUs
	}
	// Allow explicit auth_endpoint override (e.g. self-hosted) from a trusted source
	if override := viper.GetString("auth_endpoint"); override != "" {
		authEndpoint = override
	}

	// Fall back to the region default when api_url was neutralized and no
	// trusted source replaced it; the CLI must never end up with an empty host.
	apiURL := viper.GetString("api_url")
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	config := &Config{
		APIURL:           apiURL,
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
