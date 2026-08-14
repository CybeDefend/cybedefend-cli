// File: pkg/auth/store_test.go

package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// sandboxHome points the credentials store at a throw-away home directory so
// tests never touch the developer's real ~/.cybedefend.
func sandboxHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows
	return home
}

func TestSaveLoadCredentials_PersistsResolvedEndpoints(t *testing.T) {
	sandboxHome(t)

	want := &Credentials{
		Type:         AuthTypePAT,
		Region:       "eu",
		PAT:          "pat_secret",
		APIURL:       "https://api-eu.cybedefend.com",
		AuthEndpoint: "https://auth-eu.cybedefend.com",
		ClientID:     "fm90ay05zohu8fk2q45ms",
		APIResource:  "https://api-eu.cybedefend.com",
	}
	if err := SaveCredentials(want); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	got, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if got == nil {
		t.Fatal("expected credentials, got nil")
	}
	if *got != *want {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", *got, *want)
	}
}

func TestSaveCredentials_FileIsOwnerOnly(t *testing.T) {
	home := sandboxHome(t)

	if err := SaveCredentials(&Credentials{Type: AuthTypePAT, Region: "us", PAT: "pat_secret"}); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	info, err := os.Stat(filepath.Join(home, ".cybedefend", credentialsFileName))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("credentials.json must stay 0600, got %#o", perm)
	}
}

func TestEndpoints_CompleteSet(t *testing.T) {
	creds := &Credentials{
		APIURL:       "https://api-staging.cybedefend.com",
		AuthEndpoint: "https://auth-staging.cybedefend.com",
		ClientID:     "or88kgjv12sp7te58anpk",
		APIResource:  "https://api-staging.cybedefend.com",
	}

	apiURL, authEndpoint, clientID, apiResource, ok := creds.Endpoints()
	if !ok {
		t.Fatal("a complete endpoint set must be reported as usable")
	}
	if apiURL != creds.APIURL || authEndpoint != creds.AuthEndpoint ||
		clientID != creds.ClientID || apiResource != creds.APIResource {
		t.Fatalf("unexpected endpoints: %q %q %q %q", apiURL, authEndpoint, clientID, apiResource)
	}
}

func TestEndpoints_LegacyCredentialsAreNotUsable(t *testing.T) {
	// credentials.json written by CLI <= v2.0.2: only type/region/pat.
	var creds Credentials
	if err := json.Unmarshal([]byte(`{"type":"pat","region":"eu","pat":"pat_legacy"}`), &creds); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, _, _, _, ok := creds.Endpoints(); ok {
		t.Fatal("legacy credentials carry no endpoints — must fall back on the region")
	}
	if creds.Region != "eu" || creds.PAT != "pat_legacy" {
		t.Fatalf("legacy fields must still be read: %+v", creds)
	}
}

func TestEndpoints_PartialSetIsNotUsable(t *testing.T) {
	creds := &Credentials{APIURL: "https://api-eu.cybedefend.com", AuthEndpoint: "https://auth-eu.cybedefend.com"}

	if _, _, _, _, ok := creds.Endpoints(); ok {
		t.Fatal("a partial endpoint set must not be mixed with region defaults")
	}
}

func TestSaveCredentials_OmitsEmptyEndpointFields(t *testing.T) {
	home := sandboxHome(t)

	if err := SaveCredentials(&Credentials{Type: AuthTypePAT, Region: "us", PAT: "pat_secret"}); err != nil {
		t.Fatalf("SaveCredentials: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, ".cybedefend", credentialsFileName))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"api_url", "auth_endpoint", "client_id", "api_resource"} {
		if _, present := raw[key]; present {
			t.Errorf("empty %q must be omitted from credentials.json", key)
		}
	}
}

func TestLoadCredentials_MissingFileIsNotAnError(t *testing.T) {
	sandboxHome(t)

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("a missing credentials file must not be an error: %v", err)
	}
	if creds != nil {
		t.Fatalf("expected nil credentials, got %+v", creds)
	}
}
