// File: cmd/login_test.go

package cmd

import (
	"strings"
	"testing"

	"cybedefend-cli/pkg/auth"
	"cybedefend-cli/pkg/utils"
)

func euConfig() *utils.Config {
	return &utils.Config{
		AuthEndpoint:     utils.AuthEndpointEu,
		LogtoClientID:    utils.LogtoClientIDEu,
		LogtoAPIResource: utils.APIURLEu,
	}
}

func stagingConfig() *utils.Config {
	return &utils.Config{
		AuthEndpoint:     "https://auth-staging.cybedefend.com",
		LogtoClientID:    "or88kgjv12sp7te58anpk",
		LogtoAPIResource: "https://api-staging.cybedefend.com",
	}
}

func TestLoginCredentials_EURegionAndEndpointsArePersisted(t *testing.T) {
	creds, err := loginCredentials(auth.AuthTypePAT, utils.APIURLEu, euConfig(), "us", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if creds.Region != "eu" {
		t.Errorf("expected region eu, got %q", creds.Region)
	}
	if creds.APIURL != utils.APIURLEu ||
		creds.AuthEndpoint != utils.AuthEndpointEu ||
		creds.ClientID != utils.LogtoClientIDEu ||
		creds.APIResource != utils.APIURLEu {
		t.Fatalf("the four resolved endpoints must be persisted, got %+v", creds)
	}
}

func TestLoginCredentials_USRegion(t *testing.T) {
	cfg := &utils.Config{
		AuthEndpoint:     utils.AuthEndpointUs,
		LogtoClientID:    utils.LogtoClientIDUs,
		LogtoAPIResource: utils.APIURLUs,
	}

	creds, err := loginCredentials(auth.AuthTypePAT, utils.APIURLUs, cfg, "us", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Region != "us" {
		t.Errorf("expected region us, got %q", creds.Region)
	}
}

func TestLoginCredentials_KnownEndpointWinsOverRegionFlag(t *testing.T) {
	// The exchange really went to auth-eu, so the label must say eu even if
	// `--region us` was passed by mistake.
	creds, err := loginCredentials(auth.AuthTypePAT, utils.APIURLEu, euConfig(), "us", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Region != "eu" {
		t.Errorf("expected region eu (derived from the endpoint actually used), got %q", creds.Region)
	}
}

func TestLoginCredentials_KnownEndpointToleratesTrailingSlashAndCase(t *testing.T) {
	cfg := euConfig()
	cfg.AuthEndpoint = "HTTPS://AUTH-EU.CYBEDEFEND.COM/"

	creds, err := loginCredentials(auth.AuthTypePAT, utils.APIURLEu, cfg, "us", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Region != "eu" {
		t.Errorf("expected region eu, got %q", creds.Region)
	}
}

func TestLoginCredentials_UnknownEndpointWithExplicitRegion(t *testing.T) {
	creds, err := loginCredentials(auth.AuthTypePAT, "https://api-staging.cybedefend.com", stagingConfig(), "EU", true)
	if err != nil {
		t.Fatalf("an explicit --region must unblock an unknown endpoint: %v", err)
	}

	if creds.Region != "eu" {
		t.Errorf("expected the region label to be normalised to eu, got %q", creds.Region)
	}
	if creds.AuthEndpoint != "https://auth-staging.cybedefend.com" ||
		creds.APIURL != "https://api-staging.cybedefend.com" ||
		creds.ClientID != "or88kgjv12sp7te58anpk" ||
		creds.APIResource != "https://api-staging.cybedefend.com" {
		t.Fatalf("the staging endpoints used at login must be persisted, got %+v", creds)
	}
}

func TestLoginCredentials_UnknownEndpointWithoutRegionFails(t *testing.T) {
	creds, err := loginCredentials(auth.AuthTypePAT, "http://localhost:3000", &utils.Config{
		AuthEndpoint:     "http://localhost:3003",
		LogtoClientID:    "9koxa107et1i4w8tg9smo",
		LogtoAPIResource: "http://localhost:3000",
	}, "us", false)

	if err == nil {
		t.Fatal("expected an explicit error instead of a silent fallback on region us")
	}
	if creds != nil {
		t.Fatalf("no credentials must be built, got %+v", creds)
	}
	if !strings.Contains(err.Error(), "--region") {
		t.Errorf("the error must tell the user to pass --region, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "localhost:3003") {
		t.Errorf("the error must name the offending auth endpoint, got %q", err.Error())
	}
}

func TestLoginCredentials_FailureLeavesNoCredentialsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if _, err := loginCredentials(auth.AuthTypePAT, "http://localhost:3000", &utils.Config{
		AuthEndpoint: "http://localhost:3003",
	}, "us", false); err == nil {
		t.Fatal("expected an error")
	}

	stored, err := auth.LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if stored != nil {
		t.Fatalf("a failed login must not write credentials.json, got %+v", stored)
	}
}

// Non-regression for root cause B: a staging login must keep the following
// commands on staging instead of silently retargeting prod US.
func TestStagingLoginKeepsFollowingCommandsOnStaging(t *testing.T) {
	creds, err := loginCredentials(auth.AuthTypePAT, "https://api-staging.cybedefend.com", stagingConfig(), "us", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	creds.PAT = "pat_staging"

	res := resolveAuth(authInputs{APIURL: utils.APIURLUs, Creds: creds}, stubEndpoints(nil))

	if res.APIURL != "https://api-staging.cybedefend.com" {
		t.Fatalf("expected the next command to stay on staging, got %q", res.APIURL)
	}
	if res.AuthEndpoint != "https://auth-staging.cybedefend.com" {
		t.Fatalf("expected the staging auth endpoint, got %q", res.AuthEndpoint)
	}
	if res.ClientID != "or88kgjv12sp7te58anpk" {
		t.Fatalf("expected the staging Logto client id, got %q", res.ClientID)
	}
}

// Non-regression for prod EU/US: a legacy credentials.json (region only) keeps
// resolving through regionEndpoints.
func TestLegacyProdCredentialsStillResolve(t *testing.T) {
	for _, region := range []string{"eu", "us"} {
		called := false
		res := resolveAuth(authInputs{
			APIURL: utils.APIURLUs,
			Creds:  &auth.Credentials{Type: auth.AuthTypePAT, Region: region, PAT: "pat_legacy"},
		}, stubEndpoints(&called))

		if !called {
			t.Fatalf("region %s: expected the region fallback to be used", region)
		}
		if res.PAT != "pat_legacy" || res.Source != sourceStored {
			t.Fatalf("region %s: expected the legacy stored PAT, got %+v", region, res)
		}
	}
}
