// File: pkg/utils/config_test.go

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

func TestIsTrustedConfigFile(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "home", "victim")
	trustedDirs := []string{
		filepath.Join(home, ".cybedefend"),
		filepath.Join(string(filepath.Separator), "etc", "cybedefend"),
	}
	repo := filepath.Join(string(filepath.Separator), "builds", "cloned-repo")

	cases := []struct {
		name       string
		configFile string
		explicit   string
		want       bool
	}{
		{
			name:       "no config file at all",
			configFile: "",
			want:       true,
		},
		{
			name:       "user global config",
			configFile: filepath.Join(home, ".cybedefend", "config.yaml"),
			want:       true,
		},
		{
			name:       "system wide config",
			configFile: filepath.Join(string(filepath.Separator), "etc", "cybedefend", "config.yaml"),
			want:       true,
		},
		{
			name:       "config file named explicitly with --config",
			configFile: filepath.Join(repo, "config.yml"),
			explicit:   filepath.Join(repo, "config.yml"),
			want:       true,
		},
		{
			// The attack: `cybedefend scan --dir .` from the root of a cloned
			// repository picks up the repository's own config.yml.
			name:       "config discovered in the scanned repository",
			configFile: filepath.Join(repo, "config.yml"),
			want:       false,
		},
		{
			name:       "config in a subdirectory of a trusted dir",
			configFile: filepath.Join(home, ".cybedefend", "nested", "config.yaml"),
			want:       false,
		},
		{
			name:       "lookalike directory next to a trusted one",
			configFile: filepath.Join(home, ".cybedefend-evil", "config.yaml"),
			want:       false,
		},
		{
			name:       "explicit --config pointing somewhere else does not bless a discovered file",
			configFile: filepath.Join(repo, "config.yml"),
			explicit:   filepath.Join(home, ".cybedefend", "config.yaml"),
			want:       false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsTrustedConfigFile(tc.configFile, tc.explicit, trustedDirs)
			if got != tc.want {
				t.Fatalf("IsTrustedConfigFile(%q, %q) = %v, want %v", tc.configFile, tc.explicit, got, tc.want)
			}
		})
	}
}

func TestIsTrustedConfigFileNormalisesPaths(t *testing.T) {
	home := t.TempDir()
	trustedDirs := []string{filepath.Join(home, ".cybedefend")}

	messy := filepath.Join(home, ".cybedefend", "..", ".cybedefend", ".", "config.yaml")
	if !IsTrustedConfigFile(messy, "", trustedDirs) {
		t.Fatalf("IsTrustedConfigFile(%q) = false, want true after path cleaning", messy)
	}

	escaping := filepath.Join(home, ".cybedefend", "..", "config.yaml")
	if IsTrustedConfigFile(escaping, "", trustedDirs) {
		t.Fatalf("IsTrustedConfigFile(%q) = true, want false", escaping)
	}
}

// writeConfig writes a config.yml carrying the full attack payload and returns
// its path.
func writeConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yml")
	content := "" +
		"api_url: \"http://attacker.example/api\"\n" +
		"auth_endpoint: \"http://attacker.example/auth\"\n" +
		"pat: \"pat_planted_by_the_repository\"\n" +
		"project_id: \"11111111-2222-3333-4444-555555555555\"\n" +
		"branch: \"main\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("cannot write config: %v", err)
	}
	return path
}

func loadInto(t *testing.T, v *viper.Viper, path string) {
	t.Helper()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("cannot read config %s: %v", path, err)
	}
}

// A config file sitting in the working directory must not be able to redirect
// the PAT, the auth endpoint or the API URL.
func TestEnforceConfigTrustBoundaryNeutralizesWorkingDirectoryConfig(t *testing.T) {
	repo := t.TempDir()
	path := writeConfig(t, repo)

	v := viper.New()
	loadInto(t, v, path)

	// Sanity: without the boundary the attacker's values are live.
	if v.GetString("pat") != "pat_planted_by_the_repository" {
		t.Fatalf("precondition failed, pat = %q", v.GetString("pat"))
	}

	trusted, neutralized := EnforceConfigTrustBoundary(v, "")
	if trusted {
		t.Fatal("EnforceConfigTrustBoundary reported a working-directory config as trusted")
	}
	if len(neutralized) != len(SensitiveConfigKeys) {
		t.Fatalf("neutralized = %v, want all of %v", neutralized, SensitiveConfigKeys)
	}

	for _, key := range SensitiveConfigKeys {
		if got := v.GetString(key); got != "" {
			t.Fatalf("%s = %q after enforcement, want empty", key, got)
		}
	}

	// Non-sensitive project settings are the legitimate use of a repo-local
	// config file and must survive.
	if got := v.GetString("project_id"); got != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("project_id = %q, want it preserved", got)
	}
	if got := v.GetString("branch"); got != "main" {
		t.Fatalf("branch = %q, want it preserved", got)
	}
}

func TestEnforceConfigTrustBoundaryHonoursTrustedConfig(t *testing.T) {
	home := t.TempDir()
	trustedDir := filepath.Join(home, ".cybedefend")
	if err := os.MkdirAll(trustedDir, 0o700); err != nil {
		t.Fatalf("cannot create %s: %v", trustedDir, err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows

	path := writeConfig(t, trustedDir)

	v := viper.New()
	loadInto(t, v, path)

	trusted, neutralized := EnforceConfigTrustBoundary(v, "")
	if !trusted {
		t.Fatalf("config in %s reported as untrusted", trustedDir)
	}
	if len(neutralized) != 0 {
		t.Fatalf("neutralized = %v, want none", neutralized)
	}
	if got := v.GetString("pat"); got != "pat_planted_by_the_repository" {
		t.Fatalf("pat = %q, want the value from the trusted config", got)
	}
	if got := v.GetString("auth_endpoint"); got != "http://attacker.example/auth" {
		t.Fatalf("auth_endpoint = %q, want the value from the trusted config", got)
	}
}

func TestEnforceConfigTrustBoundaryHonoursExplicitConfigFlag(t *testing.T) {
	repo := t.TempDir()
	path := writeConfig(t, repo)

	v := viper.New()
	loadInto(t, v, path)

	trusted, neutralized := EnforceConfigTrustBoundary(v, path)
	if !trusted {
		t.Fatal("a config file named with --config must be trusted")
	}
	if len(neutralized) != 0 {
		t.Fatalf("neutralized = %v, want none", neutralized)
	}
	if got := v.GetString("pat"); got != "pat_planted_by_the_repository" {
		t.Fatalf("pat = %q, want the value from the explicitly named config", got)
	}
}

// The environment and command-line flags stay authoritative: neutralising the
// config layer must not shadow a value the operator supplied themselves.
func TestEnforceConfigTrustBoundaryKeepsEnvironmentOverride(t *testing.T) {
	repo := t.TempDir()
	path := writeConfig(t, repo)

	v := viper.New()
	v.SetEnvPrefix("CYBEDEFEND")
	v.AutomaticEnv()
	t.Setenv("CYBEDEFEND_PAT", "pat_from_the_operator")
	loadInto(t, v, path)

	if _, _ = EnforceConfigTrustBoundary(v, ""); v.GetString("pat") != "pat_from_the_operator" {
		t.Fatalf("pat = %q, want the environment value", v.GetString("pat"))
	}
	if got := v.GetString("api_url"); got != "" {
		t.Fatalf("api_url = %q, want empty (no trusted source supplied it)", got)
	}
}

func TestEnforceConfigTrustBoundaryIsIdempotent(t *testing.T) {
	repo := t.TempDir()
	path := writeConfig(t, repo)

	v := viper.New()
	loadInto(t, v, path)

	EnforceConfigTrustBoundary(v, "")
	// A later viper.Set (as the root command does for the region-derived API
	// URL) must survive a second enforcement pass.
	v.Set("api_url", APIURLEu)
	EnforceConfigTrustBoundary(v, "")

	if got := v.GetString("api_url"); got != APIURLEu {
		t.Fatalf("api_url = %q, want %q", got, APIURLEu)
	}
	if got := v.GetString("pat"); got != "" {
		t.Fatalf("pat = %q, want empty", got)
	}
}

// A hostile config value that is not a string must be neutralised too.
func TestEnforceConfigTrustBoundaryHandlesNonStringValues(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, "config.yml")
	if err := os.WriteFile(path, []byte("pat: 1234567890\napi_url: 42\n"), 0o600); err != nil {
		t.Fatalf("cannot write config: %v", err)
	}

	v := viper.New()
	loadInto(t, v, path)

	EnforceConfigTrustBoundary(v, "")

	if got := v.GetString("pat"); got != "" {
		t.Fatalf("pat = %q, want empty", got)
	}
	if got := v.GetString("api_url"); got != "" {
		t.Fatalf("api_url = %q, want empty", got)
	}
}

func TestTrustedConfigDirsIncludesHomeAndEtc(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	dirs := TrustedConfigDirs()

	wantHome := filepath.Join(home, ".cybedefend")
	var foundHome, foundEtc bool
	for _, d := range dirs {
		if d == wantHome {
			foundHome = true
		}
		if d == filepath.Clean("/etc/cybedefend") {
			foundEtc = true
		}
	}
	if !foundHome {
		t.Fatalf("TrustedConfigDirs() = %v, want it to contain %q", dirs, wantHome)
	}
	if !foundEtc {
		t.Fatalf("TrustedConfigDirs() = %v, want it to contain /etc/cybedefend", dirs)
	}
}
