package utils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
)

// instanceServer stands in for a CybeDefend deployment that is neither of the
// two regions. Its /client-apps names its own CLI application and its own token
// resource, which is exactly what the token exchange has to present.
func instanceServer(t *testing.T, appID string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client-apps" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"cli":{"appId":%q},"logtoResource":%q}`, appID, "http://"+r.Host)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// isolateConfig keeps LoadConfig away from the developer's real config file and
// from state left by another test.
func isolateConfig(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	viper.Reset()
	t.Cleanup(viper.Reset)
}

// The resource is the audience of the token and the client id identifies the
// application on the instance that mints it. Both belong to the API being
// called, so both must follow api_url. Deriving them from the region instead
// sends a production client id and a production resource to whatever auth
// server is in use, and the exchange fails with an opaque invalid_grant.
func TestLoadConfig_ClientIDAndResourceFollowAPIURL(t *testing.T) {
	isolateConfig(t)
	instance := instanceServer(t, "instance-cli-app")
	viper.Set("api_url", instance.URL)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned %v", err)
	}

	if cfg.AuthResource != instance.URL {
		t.Errorf("auth resource = %q, want the API being called (%q)", cfg.AuthResource, instance.URL)
	}
	if cfg.AuthClientID != "instance-cli-app" {
		t.Errorf("auth client id = %q, want the client id of the instance being called", cfg.AuthClientID)
	}
}

// The two regions must keep resolving exactly as before: there, api_url already
// is the region's URL, so following it changes nothing.
func TestLoadConfig_RegionEndpointsAreUnchanged(t *testing.T) {
	isolateConfig(t)
	viper.Set("region", "eu")
	viper.Set("api_url", APIURLEu)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned %v", err)
	}
	if cfg.AuthEndpoint != AuthEndpointEu {
		t.Errorf("auth endpoint = %q, want %q", cfg.AuthEndpoint, AuthEndpointEu)
	}
	if cfg.AuthResource != APIURLEu {
		t.Errorf("auth resource = %q, want %q", cfg.AuthResource, APIURLEu)
	}
}

// An instance whose /client-apps cannot be reached still has to present its own
// URL as the resource: the audience of the token is the API being called,
// discovery or not.
func TestLoadConfig_ResourceStillFollowsAPIURLWhenDiscoveryFails(t *testing.T) {
	isolateConfig(t)
	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(unreachable.Close)
	viper.Set("api_url", unreachable.URL)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned %v", err)
	}
	if cfg.AuthResource != unreachable.URL {
		t.Errorf("auth resource = %q, want %q", cfg.AuthResource, unreachable.URL)
	}
}

// An explicit auth endpoint stays the way to point at the auth server of an
// instance that is not a region: /client-apps does not advertise one.
func TestLoadConfig_AuthEndpointOverrideWins(t *testing.T) {
	isolateConfig(t)
	instance := instanceServer(t, "instance-cli-app")
	viper.Set("api_url", instance.URL)
	viper.Set("auth_endpoint", "https://auth.instance.example")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig returned %v", err)
	}
	if cfg.AuthEndpoint != "https://auth.instance.example" {
		t.Errorf("auth endpoint = %q, want the explicit override", cfg.AuthEndpoint)
	}
}
