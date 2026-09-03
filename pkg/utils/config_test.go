package utils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// When discovery fails against an instance that is not one of the two regions,
// there is no usable identity to fall back to: the regions' client applications
// belong to the cloud and are unknown to any other deployment. Sending one
// anyway turned a reachability problem into `invalid_client <the cloud's id>`,
// which points at the wrong thing entirely. It has to fail, and say why.
func TestLoadConfig_DiscoveryFailureIsFatalForANonRegionInstance(t *testing.T) {
	isolateConfig(t)
	unreachable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	t.Cleanup(unreachable.Close)
	viper.Set("api_url", unreachable.URL)

	cfg, err := LoadConfig()
	if err == nil {
		t.Fatalf("expected an error, got a config with client id %q", cfg.AuthClientID)
	}
	for _, want := range []string{unreachable.URL, "client-apps", "403"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// The two regions keep their built-in client application, so a momentary
// failure to reach /client-apps on the cloud does not stop a scan.
func TestRegionFallbackFor(t *testing.T) {
	for _, tc := range []struct {
		apiURL string
		want   string
		wantOK bool
	}{
		{APIURLUs, AuthClientIDUs, true},
		{APIURLEu, AuthClientIDEu, true},
		{APIURLUs + "/", AuthClientIDUs, true},
		{"https://api.self-hosted.example", "", false},
	} {
		got, ok := regionFallbackFor(tc.apiURL)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("regionFallbackFor(%q) = (%q, %v), want (%q, %v)", tc.apiURL, got, ok, tc.want, tc.wantOK)
		}
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
