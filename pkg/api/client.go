package api

import (
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
	LogtoEndpoint string
	LogtoClientID string
	APIResource   string // sent as `resource` in token exchange (same as APIURL)

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

func NewClient(apiURL, pat, logtoEndpoint, logtoClientID, logtoAPIResource string) *Client {
	return &Client{
		APIURL:        apiURL,
		PAT:           pat,
		LogtoEndpoint: logtoEndpoint,
		LogtoClientID: logtoClientID,
		APIResource:   logtoAPIResource,
	}
}

// GetAccessToken returns a valid Bearer access token, refreshing via token exchange if needed.
func (c *Client) GetAccessToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}

	return c.exchangeToken()
}

// exchangeToken performs the Logto PAT → access token exchange.
func (c *Client) exchangeToken() (string, error) {
	if c.PAT == "" {
		return "", fmt.Errorf("authentication required: provide a PAT via --pat flag, CYBEDEFEND_PAT env variable, or pat field in config file. Create one at Account Settings → Personal Access Tokens")
	}

	tokenURL := fmt.Sprintf("%s/oidc/token", strings.TrimRight(c.LogtoEndpoint, "/"))

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
