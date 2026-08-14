// File: pkg/api/client_test.go

package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"cybedefend-cli/pkg/auth"
)

func sandboxHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows
}

// The token exchange must go to the endpoints carried by the client, with the
// client id and resource of that same instance — mixing them up is what produces
// the opaque invalid_client / invalid_target / invalid_grant failures.
func TestExchangeToken_UsesTheClientEndpoints(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oidc/token" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		got = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-1","expires_in":600}`))
	}))
	defer srv.Close()

	client := NewClient("https://api.self-hosted.example", "pat_self_hosted", srv.URL,
		"self-hosted-client-id", "https://api.self-hosted.example")

	token, err := client.GetAccessToken()
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if token != "access-1" {
		t.Errorf("expected access-1, got %q", token)
	}
	if got.Get("client_id") != "self-hosted-client-id" {
		t.Errorf("unexpected client_id %q", got.Get("client_id"))
	}
	if got.Get("resource") != "https://api.self-hosted.example" {
		t.Errorf("unexpected resource %q", got.Get("resource"))
	}
	if got.Get("subject_token") != "pat_self_hosted" {
		t.Errorf("unexpected subject_token %q", got.Get("subject_token"))
	}
}

// Refreshing an OAuth token rewrites credentials.json: it must not drop the
// endpoints persisted at login time, or the command after the refresh falls back
// on the region and silently jumps to another instance.
func TestResolveOAuthToken_RefreshPreservesStoredEndpoints(t *testing.T) {
	sandboxHome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}`))
	}))
	defer srv.Close()

	stored := &auth.Credentials{
		Type:         auth.AuthTypeOAuth,
		Region:       "eu",
		APIURL:       "https://api.self-hosted.example",
		AuthEndpoint: srv.URL,
		ClientID:     "self-hosted-client-id",
		APIResource:  "https://api.self-hosted.example",
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		TokenExpiry:  time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	if err := auth.SaveCredentials(stored); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	client := NewClientWithOAuth(stored.APIURL, stored.AuthEndpoint, stored.ClientID, stored.APIResource,
		stored.AccessToken, stored.RefreshToken, time.Now().Add(-time.Hour), stored.Region)

	token, err := client.GetAccessToken()
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if token != "access-2" {
		t.Errorf("expected the refreshed token, got %q", token)
	}

	after, err := auth.LoadCredentials()
	if err != nil || after == nil {
		t.Fatalf("LoadCredentials: %v (%+v)", err, after)
	}
	if after.AccessToken != "access-2" || after.RefreshToken != "refresh-2" {
		t.Errorf("refreshed tokens not persisted: %+v", after)
	}
	if after.APIURL != stored.APIURL || after.AuthEndpoint != stored.AuthEndpoint ||
		after.ClientID != stored.ClientID || after.APIResource != stored.APIResource {
		t.Fatalf("the endpoints persisted at login must survive a refresh, got %+v", after)
	}
	if after.Region != "eu" {
		t.Errorf("expected region eu, got %q", after.Region)
	}
}

func TestResolveOAuthToken_ValidTokenIsReusedWithoutRefresh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no refresh expected while the access token is still valid")
	}))
	defer srv.Close()

	client := NewClientWithOAuth("https://api-eu.cybedefend.com", srv.URL, "client-eu", "https://api-eu.cybedefend.com",
		"access-1", "refresh-1", time.Now().Add(time.Hour), "eu")

	token, err := client.GetAccessToken()
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}
	if token != "access-1" {
		t.Errorf("expected the stored token, got %q", token)
	}
}

func TestExchangeToken_WithoutPATIsAnActionableError(t *testing.T) {
	client := NewClient("https://api-us.cybedefend.com", "", "https://auth-us.cybedefend.com", "client-us", "https://api-us.cybedefend.com")

	if _, err := client.GetAccessToken(); err == nil {
		t.Fatal("expected an authentication error")
	}
}
