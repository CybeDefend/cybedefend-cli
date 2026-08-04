// File: cmd/root_test.go

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"cybedefend-cli/pkg/utils"

	"github.com/spf13/viper"
)

const (
	attackerAPIURL       = "http://attacker.example/api"
	attackerAuthEndpoint = "http://attacker.example/auth"
	attackerPAT          = "pat_planted_by_the_repository"
	projectIDInConfig    = "11111111-2222-3333-4444-555555555555"
)

const hostileConfig = `api_url: "` + attackerAPIURL + `"
auth_endpoint: "` + attackerAuthEndpoint + `"
pat: "` + attackerPAT + `"
project_id: "` + projectIDInConfig + `"
branch: "main"
`

// unsetEnv clears CYBEDEFEND_* variables the developer may have exported, and
// restores them when the test ends.
func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		t.Setenv(key, "") // registers the restore
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("cannot unset %s: %v", key, err)
		}
	}
}

// runInitConfig runs the root command's config initialisation with workdir as
// the current directory and explicit as the value of --config.
func runInitConfig(t *testing.T, workdir, home, explicit string) {
	t.Helper()

	unsetEnv(t, "CYBEDEFEND_API_URL", "CYBEDEFEND_PAT", "CYBEDEFEND_AUTH_ENDPOINT", "CYBEDEFEND_REGION")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows

	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot read working directory: %v", err)
	}
	if err := os.Chdir(workdir); err != nil {
		t.Fatalf("cannot chdir to %s: %v", workdir, err)
	}

	previousCfgFile := cfgFile
	cfgFile = explicit

	viper.Reset()
	bindFlagsToViper()

	t.Cleanup(func() {
		cfgFile = previousCfgFile
		isUsingConfigFile = false
		isConfigTrusted = false
		viper.Reset()
		bindFlagsToViper()
		_ = os.Chdir(previous)
	})

	initConfig()
}

func writeHostileConfig(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(hostileConfig), 0o600); err != nil {
		t.Fatalf("cannot write %s: %v", path, err)
	}
	return path
}

// The audited attack: `cybedefend scan --dir .` is run from the root of a cloned
// repository that ships its own config.yml. The file must not be able to point
// the PAT exchange or the source-tree upload at the attacker.
func TestInitConfigIgnoresSensitiveKeysFromWorkingDirectory(t *testing.T) {
	repo := t.TempDir()
	home := t.TempDir()
	writeHostileConfig(t, repo, "config.yml")

	runInitConfig(t, repo, home, "")

	if isConfigTrusted {
		t.Fatal("a config file discovered in the working directory was treated as trusted")
	}
	if got := viper.GetString("pat"); got != "" {
		t.Fatalf("pat = %q, want empty — the repository must not be able to inject a token", got)
	}
	if got := viper.GetString("auth_endpoint"); got != "" {
		t.Fatalf("auth_endpoint = %q, want empty — the raw PAT must not be redirected", got)
	}
	if got := viper.GetString("api_url"); got != utils.APIURLUs {
		t.Fatalf("api_url = %q, want the region default %q", got, utils.APIURLUs)
	}

	// The legitimate use of a repo-local config file still works.
	if got := viper.GetString("project_id"); got != projectIDInConfig {
		t.Fatalf("project_id = %q, want %q", got, projectIDInConfig)
	}
	if got := viper.GetString("branch"); got != "main" {
		t.Fatalf("branch = %q, want %q", got, "main")
	}
}

func TestInitConfigHonoursHomeConfig(t *testing.T) {
	repo := t.TempDir()
	home := t.TempDir()
	globalDir := filepath.Join(home, ".cybedefend")
	if err := os.MkdirAll(globalDir, 0o700); err != nil {
		t.Fatalf("cannot create %s: %v", globalDir, err)
	}
	writeHostileConfig(t, globalDir, "config.yaml")

	runInitConfig(t, repo, home, "")

	if !isConfigTrusted {
		t.Fatal("the user's own $HOME/.cybedefend config was treated as untrusted")
	}
	if got := viper.GetString("pat"); got != attackerPAT {
		t.Fatalf("pat = %q, want the value from the user's global config", got)
	}
	if got := viper.GetString("auth_endpoint"); got != attackerAuthEndpoint {
		t.Fatalf("auth_endpoint = %q, want the value from the user's global config", got)
	}
	if got := viper.GetString("api_url"); got != attackerAPIURL {
		t.Fatalf("api_url = %q, want the value from the user's global config", got)
	}
}

func TestInitConfigHonoursExplicitConfigFlag(t *testing.T) {
	repo := t.TempDir()
	home := t.TempDir()
	path := writeHostileConfig(t, repo, "config.yml")

	runInitConfig(t, repo, home, path)

	if !isConfigTrusted {
		t.Fatal("a config file named with --config was treated as untrusted")
	}
	if got := viper.GetString("pat"); got != attackerPAT {
		t.Fatalf("pat = %q, want the value from the explicitly named config", got)
	}
	if got := viper.GetString("api_url"); got != attackerAPIURL {
		t.Fatalf("api_url = %q, want the value from the explicitly named config", got)
	}
}

// The environment stays authoritative over a neutralised config file.
func TestInitConfigKeepsEnvironmentOverEmptiedConfig(t *testing.T) {
	repo := t.TempDir()
	home := t.TempDir()
	writeHostileConfig(t, repo, "config.yml")

	runInitConfig(t, repo, home, "")
	t.Setenv("CYBEDEFEND_PAT", "pat_from_the_operator")

	if got := viper.GetString("pat"); got != "pat_from_the_operator" {
		t.Fatalf("pat = %q, want the environment value", got)
	}
}

// A working directory with no config file at all must keep the region defaults.
func TestInitConfigWithoutConfigFile(t *testing.T) {
	repo := t.TempDir()
	home := t.TempDir()

	runInitConfig(t, repo, home, "")

	if !isConfigTrusted {
		t.Fatal("no config file at all must not be reported as untrusted")
	}
	if got := viper.GetString("api_url"); got != utils.APIURLUs {
		t.Fatalf("api_url = %q, want %q", got, utils.APIURLUs)
	}
}
