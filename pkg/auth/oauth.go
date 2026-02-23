// File: pkg/auth/oauth.go

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	callbackPort = "9877"
	callbackPath = "/callback"
	redirectURI  = "http://localhost:9877/callback"
)

// OAuthResult contains the tokens returned after a successful OAuth flow.
type OAuthResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int    // seconds
	Scope        string // scopes granted by the server (empty = no API permissions)
}

// generateCodeVerifier creates a random PKCE code_verifier (43–128 chars, URL-safe).
func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateCodeChallenge derives the S256 code_challenge from a verifier.
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateState creates a random state parameter.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// openBrowser opens the given URL in the user's default browser.
func openBrowser(rawURL string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{rawURL}
	case "linux":
		cmd = "xdg-open"
		args = []string{rawURL}
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
	return exec.Command(cmd, args...).Start()
}

const callbackPageBase = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CybeDefend — Authentication</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: radial-gradient(ellipse at 60%% 10%%, #2d1045 0%%, #14082a 50%%, #0a0414 100%%);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      color: #e8d8ff;
    }
    .card {
      background: #ffffff;
      border: none;
      border-radius: 20px;
      padding: 48px 52px;
      max-width: 480px;
      width: 100%%;
      text-align: center;
      box-shadow: 0 8px 48px rgba(0,0,0,0.5);
    }
    h1 { color: #1a0a2e; }
    p  { color: rgba(40,20,60,0.6); }
    .tag { border-color: rgba(100,50,180,0.25); color: rgba(100,50,180,0.5); }
    .logo { height: 44px; margin-bottom: 36px; }
    .icon {
      width: 72px; height: 72px;
      border-radius: 50%%;
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 24px;
      font-size: 32px;
    }
    .icon.success { background: #e6f9ee; border: 1px solid #4caf7d; }
    .icon.error   { background: rgba(255,80,80,0.08);  border: 1px solid rgba(255,80,80,0.25);  }
    h1 { font-size: 22px; font-weight: 600; margin-bottom: 10px; }
    p  { font-size: 14px; line-height: 1.6; }
    .detail {
      margin-top: 16px;
      padding: 12px 16px;
      background: rgba(255,80,80,0.06);
      border: 1px solid rgba(255,80,80,0.18);
      border-radius: 10px;
      font-size: 13px;
      color: rgba(200,40,40,0.85);
      word-break: break-word;
    }
    .tag {
      display: inline-block;
      margin-top: 28px;
      padding: 5px 14px;
      border-radius: 99px;
      font-size: 11px;
      letter-spacing: 0.05em;
      text-transform: uppercase;
    }
  </style>
</head>
<body>
  <div class="card">
    <img class="logo" src="https://eu.cybedefend.com/logo.webp" alt="CybeDefend" />
    %s
    <span class="tag">CybeDefend CLI</span>
  </div>
</body>
</html>`

const callbackSuccessBody = `
    <div class="icon success">
      <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="#1a7a40" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
    </div>
    <h1>Authentication successful</h1>
    <p>You're now logged in. You can close this tab and return to your terminal.</p>`

func callbackErrorBody(title, detail string) string {
	return fmt.Sprintf(`
    <div class="icon error">✕</div>
    <h1>%s</h1>
    <p>Authentication could not be completed.</p>
    <div class="detail">%s</div>`, title, detail)
}


//  1. Start local HTTP server on :9877
//  2. Open browser to authorize URL
//  3. Wait for callback with code
//  4. Exchange code for tokens
//  5. Return tokens
func RunOAuthFlow(authEndpoint, clientID, apiResource string) (*OAuthResult, error) {
	// Generate PKCE pair
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	codeChallenge := generateCodeChallenge(codeVerifier)

	state, err := generateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Build authorize URL
	authorizeURL := fmt.Sprintf("%s/oidc/auth", strings.TrimRight(authEndpoint, "/"))

	params := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid offline_access"},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"prompt":                {"consent"}, // required for Logto to issue a refresh_token
	}
	if apiResource != "" {
		params.Set("resource", apiResource)
	}
	fullURL := authorizeURL + "?" + params.Encode()

	fmt.Printf("\nIf the browser does not open, copy this URL and open it manually:\n%s\n\n", fullURL)

	// Channel for the result
	type callbackResult struct {
		code string
		err  error
	}
	resultCh := make(chan callbackResult, 1)

	// Start local server
	mux := http.NewServeMux()
	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Check for errors from the authorization server
		if errParam := q.Get("error"); errParam != "" {
			desc := q.Get("error_description")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, callbackPageBase, callbackErrorBody("Authorization denied", errParam+": "+desc))
			resultCh <- callbackResult{err: fmt.Errorf("authorization error: %s — %s", errParam, desc)}
			return
		}

		// Verify state
		if q.Get("state") != state {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, callbackPageBase, callbackErrorBody("Security check failed", "Invalid state parameter. Please try logging in again."))
			resultCh <- callbackResult{err: fmt.Errorf("state mismatch")}
			return
		}

		code := q.Get("code")
		if code == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, callbackPageBase, callbackErrorBody("No authorization code", "The authorization server did not return a code. Please try again."))
			resultCh <- callbackResult{err: fmt.Errorf("no authorization code in callback")}
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, callbackPageBase, callbackSuccessBody)
		resultCh <- callbackResult{code: code}
	})

	listener, err := net.Listen("tcp", ":"+callbackPort)
	if err != nil {
		return nil, fmt.Errorf("cannot start callback server on port %s: %w", callbackPort, err)
	}
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	// Open browser
	if err := openBrowser(fullURL); err != nil {
		return nil, fmt.Errorf("cannot open browser: %w\n\nPlease open this URL manually:\n%s", err, fullURL)
	}

	// Wait for callback (timeout: 5 minutes)
	select {
	case res := <-resultCh:
		if res.err != nil {
			return nil, res.err
		}
		// Exchange code for tokens
		return exchangeAuthorizationCode(authEndpoint, clientID, res.code, codeVerifier, apiResource)
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("login timed out after 5 minutes — no callback received")
	}
}

// exchangeAuthorizationCode exchanges the authorization code for tokens.
func exchangeAuthorizationCode(authEndpoint, clientID, code, codeVerifier, apiResource string) (*OAuthResult, error) {
	tokenURL := fmt.Sprintf("%s/oidc/token", strings.TrimRight(authEndpoint, "/"))

	data := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	}
	if apiResource != "" {
		data.Set("resource", apiResource)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error parsing token response: %w", err)
	}

	if result.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in token response")
	}

	return &OAuthResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}

// RefreshAccessToken uses a refresh token to obtain a new access token.
func RefreshAccessToken(authEndpoint, clientID, refreshToken, apiResource string) (*OAuthResult, error) {
	tokenURL := fmt.Sprintf("%s/oidc/token", strings.TrimRight(authEndpoint, "/"))

	data := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if apiResource != "" {
		data.Set("resource", apiResource)
	}

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error building refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error parsing refresh response: %w", err)
	}

	if result.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in refresh response")
	}

	return &OAuthResult{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}, nil
}
