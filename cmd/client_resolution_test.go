// File: cmd/client_resolution_test.go

package cmd

import (
	"strings"
	"testing"

	"cybedefend-cli/pkg/auth"
	"cybedefend-cli/pkg/utils"

	"github.com/spf13/viper"
)

// stubEndpoints stands in for regionEndpoints so tests never hit the network
// (the real one calls /client-apps). It also records whether it was consulted.
func stubEndpoints(called *bool) func(string) (string, string, string, string) {
	return func(region string) (string, string, string, string) {
		if called != nil {
			*called = true
		}
		if region == "eu" {
			return "https://api-eu.example", "https://auth-eu.example", "client-eu", "https://api-eu.example"
		}
		return "https://api-us.example", "https://auth-us.example", "client-us", "https://api-us.example"
	}
}

func storedPATCredentials() *auth.Credentials {
	return &auth.Credentials{
		Type:         auth.AuthTypePAT,
		Region:       "eu",
		PAT:          "pat_from_login",
		APIURL:       "https://api-eu.cybedefend.com",
		AuthEndpoint: "https://auth-eu.cybedefend.com",
		ClientID:     "client-eu",
		APIResource:  "https://api-eu.cybedefend.com",
	}
}

// configInputs mimics what viper resolves when a `pat:` sits in config.yaml.
func configInputs() authInputs {
	return authInputs{
		PAT:          "pat_from_config",
		APIURL:       "https://api-us.cybedefend.com",
		AuthEndpoint: "https://auth-us.cybedefend.com",
		ClientID:     "client-us",
		APIResource:  "https://api-us.cybedefend.com",
	}
}

func countWarnings(warnings []string, substr string) int {
	n := 0
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			n++
		}
	}
	return n
}

// ── Lot 1: credential priority ───────────────────────────────────────

func TestResolveAuth_ConfigPATLosesAgainstStoredCredentials(t *testing.T) {
	in := configInputs()
	in.PATInConfigFile = true
	in.Creds = storedPATCredentials()

	res := resolveAuth(in, stubEndpoints(nil))

	if res.Source != sourceStored {
		t.Fatalf("expected the stored credentials to win, got source %q", res.Source)
	}
	if res.PAT != "pat_from_login" {
		t.Errorf("expected the PAT written by `login`, got %q", res.PAT)
	}
	if res.APIURL != "https://api-eu.cybedefend.com" {
		t.Errorf("expected the API URL of the stored credentials, got %q", res.APIURL)
	}
}

func TestResolveAuth_EnvPATLosesAgainstStoredCredentials(t *testing.T) {
	// $CYBEDEFEND_PAT reaches us through viper exactly like a config value,
	// minus the `pat:` key in the file.
	in := configInputs()
	in.PATInConfigFile = false
	in.Creds = storedPATCredentials()

	res := resolveAuth(in, stubEndpoints(nil))

	if res.Source != sourceStored {
		t.Fatalf("expected the stored credentials to win over $CYBEDEFEND_PAT, got source %q", res.Source)
	}
	if res.PAT != "pat_from_login" {
		t.Errorf("expected the PAT written by `login`, got %q", res.PAT)
	}
	if countWarnings(res.Warnings, "deprecated") != 0 {
		t.Errorf("no config file involved, so no deprecation warning expected: %v", res.Warnings)
	}
}

func TestResolveAuth_ExplicitPATFlagWinsOverStoredCredentials(t *testing.T) {
	in := configInputs()
	in.PAT = "pat_from_flag"
	in.PATFlagChanged = true
	in.Creds = storedPATCredentials()

	res := resolveAuth(in, stubEndpoints(nil))

	if res.Source != sourceFlagPAT {
		t.Fatalf("expected the explicit --pat flag to win, got source %q", res.Source)
	}
	if res.PAT != "pat_from_flag" {
		t.Errorf("expected the flag PAT, got %q", res.PAT)
	}
	if res.AuthEndpoint != in.AuthEndpoint {
		t.Errorf("an explicit --pat must use the current config endpoints, got %q", res.AuthEndpoint)
	}
}

func TestResolveAuth_EmptyPATFlagDoesNotShadowStoredCredentials(t *testing.T) {
	in := configInputs()
	in.PAT = ""
	in.PATFlagChanged = true
	in.Creds = storedPATCredentials()

	res := resolveAuth(in, stubEndpoints(nil))

	if res.Source != sourceStored {
		t.Fatalf("an empty --pat must not shadow the stored credentials, got source %q", res.Source)
	}
}

func TestResolveAuth_ConfigPATUsedWhenNoStoredCredentials(t *testing.T) {
	in := configInputs()
	in.PATInConfigFile = true

	res := resolveAuth(in, stubEndpoints(nil))

	if res.Source != sourceConfigPAT {
		t.Fatalf("expected the config PAT to be used as a fallback, got source %q", res.Source)
	}
	if res.PAT != "pat_from_config" {
		t.Errorf("expected the config PAT, got %q", res.PAT)
	}
	if res.APIURL != in.APIURL || res.AuthEndpoint != in.AuthEndpoint {
		t.Errorf("expected the config endpoints, got %q / %q", res.APIURL, res.AuthEndpoint)
	}
}

func TestResolveAuth_AmbiguityWarningEmittedExactlyOnce(t *testing.T) {
	in := configInputs()
	in.PATInConfigFile = true
	in.Creds = storedPATCredentials()

	res := resolveAuth(in, stubEndpoints(nil))

	if got := countWarnings(res.Warnings, "lift the ambiguity"); got != 1 {
		t.Fatalf("expected exactly one ambiguity warning, got %d: %v", got, res.Warnings)
	}
}

func TestResolveAuth_NoAmbiguityWarningWithoutConfigPAT(t *testing.T) {
	in := authInputs{
		APIURL:       "https://api-us.cybedefend.com",
		AuthEndpoint: "https://auth-us.cybedefend.com",
		Creds:        storedPATCredentials(),
	}

	res := resolveAuth(in, stubEndpoints(nil))

	if len(res.Warnings) != 0 {
		t.Fatalf("expected no warning, got %v", res.Warnings)
	}
}

func TestResolveAuth_NoCredentialsAtAll(t *testing.T) {
	in := authInputs{
		APIURL:       "https://api-us.cybedefend.com",
		AuthEndpoint: "https://auth-us.cybedefend.com",
		ClientID:     "client-us",
		APIResource:  "https://api-us.cybedefend.com",
	}

	res := resolveAuth(in, stubEndpoints(nil))

	if res.Source != sourceNone {
		t.Fatalf("expected sourceNone, got %q", res.Source)
	}
	if res.PAT != "" {
		t.Errorf("expected no PAT, got %q", res.PAT)
	}
}

// ── Lot 2: stored endpoints beat the region enum ─────────────────────

func TestResolveAuth_StoredEndpointsAreUsedVerbatim(t *testing.T) {
	called := false
	in := authInputs{APIURL: "https://api-us.cybedefend.com"}
	in.Creds = &auth.Credentials{
		Type:         auth.AuthTypePAT,
		Region:       "us", // legacy default written by the buggy login
		PAT:          "pat_self_hosted",
		APIURL:       "https://api.self-hosted.example",
		AuthEndpoint: "https://auth.self-hosted.example",
		ClientID:     "self-hosted-client-id",
		APIResource:  "https://api.self-hosted.example",
	}

	res := resolveAuth(in, stubEndpoints(&called))

	if called {
		t.Error("regionEndpoints must not be consulted when the credentials carry endpoints")
	}
	if res.APIURL != "https://api.self-hosted.example" ||
		res.AuthEndpoint != "https://auth.self-hosted.example" ||
		res.ClientID != "self-hosted-client-id" ||
		res.APIResource != "https://api.self-hosted.example" {
		t.Fatalf("expected the persisted self-hosted endpoints, got %+v", res)
	}
}

func TestResolveAuth_LegacyCredentialsFallBackOnRegion(t *testing.T) {
	called := false
	in := authInputs{APIURL: "https://api-us.cybedefend.com"}
	in.Creds = &auth.Credentials{Type: auth.AuthTypePAT, Region: "eu", PAT: "pat_legacy"}

	res := resolveAuth(in, stubEndpoints(&called))

	if !called {
		t.Error("legacy credentials must fall back on regionEndpoints")
	}
	if res.APIURL != "https://api-eu.example" || res.AuthEndpoint != "https://auth-eu.example" {
		t.Fatalf("expected the region-derived EU endpoints, got %+v", res)
	}
	if res.PAT != "pat_legacy" {
		t.Errorf("expected the legacy stored PAT, got %q", res.PAT)
	}
}

func TestResolveAuth_OAuthCredentials(t *testing.T) {
	in := authInputs{APIURL: "https://api-us.cybedefend.com"}
	in.Creds = &auth.Credentials{
		Type:         auth.AuthTypeOAuth,
		Region:       "eu",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenExpiry:  "2030-01-01T00:00:00Z",
		APIURL:       "https://api-eu.cybedefend.com",
		AuthEndpoint: "https://auth-eu.cybedefend.com",
		ClientID:     "client-eu",
		APIResource:  "https://api-eu.cybedefend.com",
	}

	res := resolveAuth(in, stubEndpoints(nil))

	if res.Source != sourceStored {
		t.Fatalf("expected the stored OAuth credentials, got source %q", res.Source)
	}
	if res.OAuth == nil {
		t.Fatal("expected the OAuth credentials to be carried over")
	}
	if res.Region != "eu" {
		t.Errorf("expected region eu (used to persist refreshed tokens), got %q", res.Region)
	}
}

func TestResolveAuth_IncompleteStoredEndpointsFallBackOnRegion(t *testing.T) {
	called := false
	in := authInputs{APIURL: "https://api-us.cybedefend.com"}
	in.Creds = &auth.Credentials{
		Type:   auth.AuthTypePAT,
		Region: "eu",
		PAT:    "pat_partial",
		APIURL: "https://api-eu.cybedefend.com", // the three others are missing
	}

	res := resolveAuth(in, stubEndpoints(&called))

	if !called {
		t.Error("a partial endpoint set must not be mixed with region defaults")
	}
	if res.AuthEndpoint != "https://auth-eu.example" {
		t.Fatalf("expected the region-derived auth endpoint, got %q", res.AuthEndpoint)
	}
}

// ── Explicit flags must not be silently ignored ──────────────────────

func TestResolveAuth_ExplicitAPIURLIsReportedAsIgnored(t *testing.T) {
	in := authInputs{
		APIURL:            "https://127.0.0.1:9",
		APIURLFlagChanged: true,
		Creds:             storedPATCredentials(),
	}

	res := resolveAuth(in, stubEndpoints(nil))

	if res.APIURL != "https://api-eu.cybedefend.com" {
		t.Fatalf("stored credentials still pin the endpoint, got %q", res.APIURL)
	}
	if countWarnings(res.Warnings, "--api-url") != 1 {
		t.Fatalf("expected the ignored --api-url to be reported, got %v", res.Warnings)
	}
}

func TestResolveAuth_ExplicitAPIURLMatchingStoredIsNotReported(t *testing.T) {
	in := authInputs{
		APIURL:            "https://api-eu.cybedefend.com",
		APIURLFlagChanged: true,
		Creds:             storedPATCredentials(),
	}

	res := resolveAuth(in, stubEndpoints(nil))

	if countWarnings(res.Warnings, "--api-url") != 0 {
		t.Fatalf("no warning expected when the flag matches the stored endpoint, got %v", res.Warnings)
	}
}

func TestResolveAuth_ExplicitRegionIsReportedAsIgnored(t *testing.T) {
	in := authInputs{
		APIURL:            "https://api-us.cybedefend.com",
		RegionFlag:        "us",
		RegionFlagChanged: true,
		Creds:             storedPATCredentials(), // region eu
	}

	res := resolveAuth(in, stubEndpoints(nil))

	if countWarnings(res.Warnings, "--region") != 1 {
		t.Fatalf("expected the ignored --region to be reported, got %v", res.Warnings)
	}
}

func TestResolveAuth_ExplicitRegionMatchingStoredIsNotReported(t *testing.T) {
	in := authInputs{
		APIURL:            "https://api-eu.cybedefend.com",
		RegionFlag:        "EU",
		RegionFlagChanged: true,
		Creds:             storedPATCredentials(),
	}

	res := resolveAuth(in, stubEndpoints(nil))

	if countWarnings(res.Warnings, "--region") != 0 {
		t.Fatalf("no warning expected when the flag matches the stored region, got %v", res.Warnings)
	}
}

// ── End-to-end wiring: viper + credentials.json → api.Client ─────────

// withUSConfigAndPAT points the running command at a sandbox home and installs a
// stale config PAT, reproducing the reported setup: a `pat:` left in config.yaml.
func withUSConfigAndPAT(t *testing.T, pat string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows

	viper.Set("pat", pat)
	viper.Set("api_url", utils.APIURLUs)
	config = &utils.Config{
		AuthEndpoint:     utils.AuthEndpointUs,
		LogtoClientID:    utils.LogtoClientIDUs,
		LogtoAPIResource: utils.APIURLUs,
	}
	t.Cleanup(func() {
		viper.Set("pat", "")
		viper.Set("api_url", "")
		config = nil
	})
}

func TestNewClientFromConfig_StaleConfigPATDoesNotShadowLogin(t *testing.T) {
	withUSConfigAndPAT(t, "pat_stale_from_config")

	if err := auth.SaveCredentials(&auth.Credentials{
		Type:         auth.AuthTypePAT,
		Region:       "eu",
		PAT:          "pat_from_login",
		APIURL:       utils.APIURLEu,
		AuthEndpoint: utils.AuthEndpointEu,
		ClientID:     utils.LogtoClientIDEu,
		APIResource:  utils.APIURLEu,
	}); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	client := newClientFromConfig()

	if client.PAT != "pat_from_login" {
		t.Fatalf("the stale config PAT still shadows `cybedefend login`, got %q", client.PAT)
	}
	if client.APIURL != utils.APIURLEu || client.AuthEndpoint != utils.AuthEndpointEu {
		t.Fatalf("expected the EU endpoints of the stored credentials, got %q / %q", client.APIURL, client.AuthEndpoint)
	}
}

func TestNewClientFromConfig_ConfigPATStillWorksWithoutLogin(t *testing.T) {
	withUSConfigAndPAT(t, "pat_stale_from_config")

	client := newClientFromConfig()

	if client.PAT != "pat_stale_from_config" {
		t.Fatalf("expected the config PAT as a fallback, got %q", client.PAT)
	}
	if client.APIURL != utils.APIURLUs {
		t.Errorf("expected the config API URL, got %q", client.APIURL)
	}
}

// ── Lot 3: `pat:` in config.yaml is deprecated ───────────────────────

func TestResolveAuth_ConfigPATEmitsDeprecationWarning(t *testing.T) {
	in := configInputs()
	in.PATInConfigFile = true

	res := resolveAuth(in, stubEndpoints(nil))

	if countWarnings(res.Warnings, "deprecated") != 1 {
		t.Fatalf("expected exactly one deprecation warning, got %v", res.Warnings)
	}
}

func TestResolveAuth_NoDeprecationWarningWithoutConfigPAT(t *testing.T) {
	in := configInputs()
	in.PATInConfigFile = false

	res := resolveAuth(in, stubEndpoints(nil))

	if countWarnings(res.Warnings, "deprecated") != 0 {
		t.Fatalf("expected no deprecation warning, got %v", res.Warnings)
	}
}
