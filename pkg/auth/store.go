// File: pkg/auth/store.go

package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const credentialsFileName = "credentials.json"

// AuthType distinguishes between PAT and OAuth login methods.
type AuthType string

const (
	AuthTypePAT   AuthType = "pat"
	AuthTypeOAuth AuthType = "oauth"
)

// Credentials represents stored authentication state.
//
// Region is kept for backward compatibility with credentials.json files written
// by CLI <= v2.0.2, but it is only a label: the endpoints actually used at login
// time are persisted below and take precedence. Deriving everything from a
// two-value region enum silently retargeted staging/self-hosted logins to prod US.
type Credentials struct {
	Type   AuthType `json:"type"`
	Region string   `json:"region"`

	// Endpoints resolved at login time.
	APIURL       string `json:"api_url,omitempty"`
	AuthEndpoint string `json:"auth_endpoint,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	APIResource  string `json:"api_resource,omitempty"`

	PAT          string `json:"pat,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenExpiry  string `json:"token_expiry,omitempty"` // RFC 3339
}

// Endpoints returns the endpoints captured at login time. ok is false for legacy
// credentials, or for any incomplete set — callers then fall back on the region
// so a partial set is never mixed with region defaults.
func (c *Credentials) Endpoints() (apiURL, authEndpoint, clientID, apiResource string, ok bool) {
	if c.APIURL == "" || c.AuthEndpoint == "" || c.ClientID == "" || c.APIResource == "" {
		return "", "", "", "", false
	}
	return c.APIURL, c.AuthEndpoint, c.ClientID, c.APIResource, true
}

// IsAccessTokenValid returns true when the stored OAuth access token has not yet expired.
func (c *Credentials) IsAccessTokenValid() bool {
	if c.TokenExpiry == "" || c.AccessToken == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, c.TokenExpiry)
	if err != nil {
		return false
	}
	return time.Now().Before(t.Add(-30 * time.Second)) // 30 s safety margin
}

// credentialsDir returns ~/.cybedefend, creating it if needed.
func credentialsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".cybedefend")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create credentials directory: %w", err)
	}
	return dir, nil
}

// credentialsPath returns the full path to credentials.json.
func credentialsPath() (string, error) {
	dir, err := credentialsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, credentialsFileName), nil
}

// SaveCredentials writes credentials to ~/.cybedefend/credentials.json (mode 0600).
func SaveCredentials(creds *Credentials) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal credentials: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("cannot write credentials file: %w", err)
	}
	return nil
}

// LoadCredentials reads stored credentials. Returns nil (no error) if file doesn't exist.
func LoadCredentials() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot read credentials file: %w", err)
	}
	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("cannot parse credentials file: %w", err)
	}
	return &creds, nil
}

// DeleteCredentials removes the stored credentials file.
func DeleteCredentials() error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("cannot remove credentials file: %w", err)
	}
	return nil
}
