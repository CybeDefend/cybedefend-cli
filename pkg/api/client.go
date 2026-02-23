package api

import (
	"cybedefend-cli/pkg/auth"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Client struct {
	APIURL        string
	PAT           string
	AuthEndpoint  string
	LogtoClientID string
	APIResource   string // sent as `resource` in token exchange (same as APIURL)

	// OAuth fields (set when the user logged in via browser flow)
	OAuthAccessToken  string
	OAuthRefreshToken string
	OAuthTokenExpiry  time.Time
	OAuthRegion       string // used to persist refreshed tokens to disk

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

func NewClient(apiURL, pat, authEndpoint, logtoClientID, logtoAPIResource string) *Client {
	return &Client{
		APIURL:        apiURL,
		PAT:           pat,
		AuthEndpoint:  authEndpoint,
		LogtoClientID: logtoClientID,
		APIResource:   logtoAPIResource,
	}
}

// NewClientWithOAuth creates a Client that uses stored OAuth tokens instead of PAT.
func NewClientWithOAuth(apiURL, authEndpoint, logtoClientID, logtoAPIResource, accessToken, refreshToken string, tokenExpiry time.Time, region string) *Client {
	return &Client{
		APIURL:            apiURL,
		AuthEndpoint:      authEndpoint,
		LogtoClientID:     logtoClientID,
		APIResource:       logtoAPIResource,
		OAuthAccessToken:  accessToken,
		OAuthRefreshToken: refreshToken,
		OAuthTokenExpiry:  tokenExpiry,
		OAuthRegion:       region,
	}
}

// GetAccessToken returns a valid Bearer access token, refreshing via token exchange if needed.
func (c *Client) GetAccessToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}

	// If OAuth tokens are available, use them
	if c.OAuthAccessToken != "" {
		return c.resolveOAuthToken()
	}

	return c.exchangeToken()
}

// exchangeToken performs the Logto PAT → access token exchange.
func (c *Client) exchangeToken() (string, error) {
	if c.PAT == "" {
		return "", fmt.Errorf("authentication required: provide a PAT via --pat flag, CYBEDEFEND_PAT env variable, or pat field in config file. Create one at Account Settings → Personal Access Tokens")
	}

	tokenURL := fmt.Sprintf("%s/oidc/token", strings.TrimRight(c.AuthEndpoint, "/"))

	data := url.Values{}
	data.Set("client_id", c.LogtoClientID)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", c.PAT)
	data.Set("subject_token_type", "urn:logto:token-type:personal_access_token")
	if c.APIResource != "" {
		data.Set("resource", c.APIResource)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("token exchange request build error: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("PAT authentication failed: the token may be invalid or revoked. Generate a new PAT from Account Settings → Personal Access Tokens")
	}

	if resp.StatusCode == http.StatusBadRequest && strings.Contains(string(body), "token_exchange_not_allowed") {
		return "", fmt.Errorf("token exchange is not enabled for this application. Contact CybeDefend support")
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed (HTTP %d): %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("token exchange response parse error: %w", err)
	}

	// Cache with 30s safety margin (TTL is 600s)
	c.cachedToken = result.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn-30) * time.Second)

	return c.cachedToken, nil
}

// resolveOAuthToken returns the stored OAuth access token, refreshing it if expired.
func (c *Client) resolveOAuthToken() (string, error) {
	// Still valid? Use it.
	if time.Now().Before(c.OAuthTokenExpiry.Add(-30 * time.Second)) {
		c.cachedToken = c.OAuthAccessToken
		c.tokenExpiry = c.OAuthTokenExpiry
		return c.cachedToken, nil
	}

	// Need to refresh
	if c.OAuthRefreshToken == "" {
		return "", fmt.Errorf("OAuth access token expired and no refresh token available. Please run: cybedefend login")
	}

	tokenURL := fmt.Sprintf("%s/oidc/token", strings.TrimRight(c.AuthEndpoint, "/"))

	data := url.Values{
		"client_id":     {c.LogtoClientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.OAuthRefreshToken},
	}
	if c.APIResource != "" {
		data.Set("resource", c.APIResource)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("refresh token request build error: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("refresh token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token refresh failed (HTTP %d): %s. Please run: cybedefend login", resp.StatusCode, body)
	}

	var refreshResult struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &refreshResult); err != nil {
		return "", fmt.Errorf("refresh response parse error: %w", err)
	}

	c.OAuthAccessToken = refreshResult.AccessToken
	if refreshResult.RefreshToken != "" {
		c.OAuthRefreshToken = refreshResult.RefreshToken
	}
	c.OAuthTokenExpiry = time.Now().Add(time.Duration(refreshResult.ExpiresIn) * time.Second)

	c.cachedToken = refreshResult.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(refreshResult.ExpiresIn-30) * time.Second)

	// Persist refreshed credentials so the next CLI invocation uses the new tokens.
	if c.OAuthRegion != "" {
		expiry := c.OAuthTokenExpiry.UTC().Format(time.RFC3339)
		_ = auth.SaveCredentials(&auth.Credentials{
			Type:         auth.AuthTypeOAuth,
			Region:       c.OAuthRegion,
			AccessToken:  refreshResult.AccessToken,
			RefreshToken: c.OAuthRefreshToken,
			TokenExpiry:  expiry,
		})
	}

	return c.cachedToken, nil
}
