// File: pkg/validation/validation_test.go

package validation_test

import (
	"strings"
	"testing"

	"cybedefend-cli/pkg/api"
	"cybedefend-cli/pkg/validation"
)

// The identifiers below are interpolated into API URL paths by every client
// method, so what this rule keeps out is not cosmetic: a `/`, a `?` or a `%`
// lets a flag decide which endpoint the CLI actually calls.
func TestResourceID(t *testing.T) {
	valid := []string{
		"6f1b3c2e-9d4a-4f8b-8c1e-2a7d5b0f9e33", // the UUID shape the API issues
		"abc123",
		"project.name_v2-1",
	}
	for _, id := range valid {
		if err := validation.ResourceID("--project-id", id); err != nil {
			t.Errorf("ResourceID(%q) rejected a legitimate id: %v", id, err)
		}
	}

	rejected := map[string]string{
		"":                       "empty",
		"../../admin":            "path traversal",
		"p1/scan/start":          "extra path segments",
		"p1?admin=true":          "query injection",
		"p1#frag":                "fragment",
		"p1%2f":                  "percent-encoded separator",
		"-p1":                    "leading dash",
		"p1 p2":                  "whitespace",
		strings.Repeat("a", 129): "too long",
	}
	for id, why := range rejected {
		if err := validation.ResourceID("--project-id", id); err == nil {
			t.Errorf("ResourceID(%q) accepted %s", id, why)
		}
	}
}

// The error has to name the flag the user typed, not the Go field, or it is not
// actionable from a terminal.
func TestStructErrorNamesTheFlag(t *testing.T) {
	err := validation.Struct(validation.ResultsInput{
		ProjectID:    "p1",
		ScanType:     "sast",
		OutputFormat: "xml",
		OutputFile:   "results.json",
		OutputPath:   ".",
		Page:         1,
	})
	if err == nil {
		t.Fatal("expected an unsupported --output format to be rejected")
	}
	for _, want := range []string{"--output", "xml", "json", "sarif"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// A rejection lists every bad flag at once: fixing them one round-trip at a time
// is what the ad-hoc checks used to force.
func TestStructReportsEveryBadField(t *testing.T) {
	err := validation.Struct(validation.ResultsInput{
		ProjectID:    "../p1",
		ScanType:     "everything",
		OutputFormat: "json",
		OutputFile:   "results.json",
		OutputPath:   ".",
		Page:         1,
	})
	if err == nil {
		t.Fatal("expected both the id and the scan type to be rejected")
	}
	for _, want := range []string{"--project-id", "--type"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// The --type schema is written as a `oneof` tag, which cannot import the API
// package. This is what keeps the two in step.
func TestScanTypesMatchTheAPI(t *testing.T) {
	declared := strings.Fields(validation.ScanTypes)
	if len(declared) != len(api.ValidScanTypes) {
		t.Fatalf("validation.ScanTypes = %v, api.ValidScanTypes = %v", declared, api.ValidScanTypes)
	}
	for _, scanType := range api.ValidScanTypes {
		if err := validation.Struct(validation.ResultsInput{
			ProjectID:    "p1",
			ScanType:     scanType,
			OutputFormat: "json",
			OutputFile:   "results.json",
			OutputPath:   ".",
			Page:         1,
		}); err != nil {
			t.Errorf("scan type %q is accepted by the API package but rejected here: %v", scanType, err)
		}
	}
}

// The config is the one schema no command opts into: it is checked once, in
// LoadConfig, for every invocation.
func TestConfigInput(t *testing.T) {
	base := validation.ConfigInput{
		APIURL:       "https://api-eu.cybedefend.com",
		AuthEndpoint: "https://auth-eu.cybedefend.com",
	}
	if err := validation.Struct(base); err != nil {
		t.Fatalf("a region configuration was rejected: %v", err)
	}

	// A self-hosted deployment on plain http, reached by IP and port, is a
	// normal thing to point the CLI at.
	selfHosted := base
	selfHosted.APIURL = "http://127.0.0.1:8080"
	if err := validation.Struct(selfHosted); err != nil {
		t.Errorf("a self-hosted http endpoint was rejected: %v", err)
	}

	for _, tc := range []struct {
		name  string
		input validation.ConfigInput
	}{
		{"a bare host is not a URL", validation.ConfigInput{APIURL: "api.cybedefend.com", AuthEndpoint: base.AuthEndpoint}},
		{"a non-http scheme", validation.ConfigInput{APIURL: "file:///etc/passwd", AuthEndpoint: base.AuthEndpoint}},
		{"a missing auth endpoint", validation.ConfigInput{APIURL: base.APIURL}},
		{"an unknown region", validation.ConfigInput{APIURL: base.APIURL, AuthEndpoint: base.AuthEndpoint, Region: "fr"}},
		{"a project id with a path", validation.ConfigInput{APIURL: base.APIURL, AuthEndpoint: base.AuthEndpoint, ProjectID: "p1/../p2"}},
	} {
		if err := validation.Struct(tc.input); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

// "none" is the documented way to disable the severity gate, so it has to stay
// a valid value rather than read as "unset".
func TestScanInput(t *testing.T) {
	base := validation.ScanInput{
		ProjectID:     "p1",
		Branch:        "main",
		Directory:     ".",
		Interval:      5,
		PolicyTimeout: 300,
	}
	for _, severity := range append(strings.Fields(validation.Severities), "") {
		input := base
		input.BreakOnSeverity = severity
		if err := validation.Struct(input); err != nil {
			t.Errorf("--break-on-severity %q was rejected: %v", severity, err)
		}
	}

	// Feature branches carry slashes and dots; git itself refuses the rest.
	for _, branch := range []string{"main", "feature/CYB-123", "release-2.0.8", "v1.0"} {
		input := base
		input.Branch = branch
		if err := validation.Struct(input); err != nil {
			t.Errorf("branch %q was rejected: %v", branch, err)
		}
	}
	for _, branch := range []string{"feature branch", "a..b", "-main", "refs/heads/", "bad~name"} {
		input := base
		input.Branch = branch
		if err := validation.Struct(input); err == nil {
			t.Errorf("branch %q was accepted", branch)
		}
	}

	// A zero interval polls the scan status in a tight loop.
	zeroInterval := base
	zeroInterval.Interval = 0
	if err := validation.Struct(zeroInterval); err == nil {
		t.Error("--interval 0 was accepted")
	}
}

// Output paths belong to the user's own machine: `..` and absolute paths are
// how a CI job says where to put its artifacts, and must keep working.
func TestOutputPathsStayPermissive(t *testing.T) {
	for _, path := range []string{".", "../artifacts", "/tmp/out", "sub/dir"} {
		if err := validation.Struct(validation.ResultsInput{
			ProjectID:    "p1",
			ScanType:     "all",
			OutputFormat: "json",
			OutputFile:   "results.json",
			OutputPath:   path,
			Page:         1,
		}); err != nil {
			t.Errorf("--filepath %q was rejected: %v", path, err)
		}
	}

	if err := validation.Struct(validation.ResultsInput{
		ProjectID:    "p1",
		ScanType:     "all",
		OutputFormat: "json",
		OutputFile:   "results\x00.json",
		OutputPath:   ".",
		Page:         1,
	}); err == nil {
		t.Error("a NUL byte in --filename was accepted")
	}
}

func TestDateRangeInput(t *testing.T) {
	for _, date := range []string{"", "2026-09-08", "2026-09-08T14:30:00Z", "2026-09-08T14:30:00"} {
		if err := validation.Struct(validation.DateRangeInput{StartDate: date}); err != nil {
			t.Errorf("--start-date %q was rejected: %v", date, err)
		}
	}
	for _, date := range []string{"08/09/2026", "yesterday", "2026-13-01"} {
		if err := validation.Struct(validation.DateRangeInput{StartDate: date}); err == nil {
			t.Errorf("--start-date %q was accepted", date)
		}
	}
}

func TestContainerScanInput(t *testing.T) {
	base := validation.ContainerScanInput{ProjectID: "p1", Image: "my-app:v1.0.0"}
	if err := validation.Struct(base); err != nil {
		t.Fatalf("a plain image reference was rejected: %v", err)
	}

	for _, image := range []string{
		"ghcr.io/cybedefend/cybedefend-cli:v2.0.8",
		"registry.example.com:5000/team/app@sha256:" + strings.Repeat("a", 64),
	} {
		input := base
		input.Image = image
		if err := validation.Struct(input); err != nil {
			t.Errorf("image %q was rejected: %v", image, err)
		}
	}

	withSeverities := base
	withSeverities.Severities = []string{"CRITICAL", "HIGH"}
	if err := validation.Struct(withSeverities); err != nil {
		t.Errorf("severities CRITICAL,HIGH were rejected: %v", err)
	}

	badSeverity := base
	badSeverity.Severities = []string{"CRITICAL", "URGENT"}
	if err := validation.Struct(badSeverity); err == nil {
		t.Error("severity URGENT was accepted")
	}
}

func TestTeamMemberInput(t *testing.T) {
	for _, role := range strings.Fields(validation.TeamRoles) {
		if err := validation.Struct(validation.TeamMemberInput{
			TeamID: "t1", UserID: "u1", Role: role,
		}); err != nil {
			t.Errorf("role %q was rejected: %v", role, err)
		}
	}

	err := validation.Struct(validation.TeamMemberInput{TeamID: "t1", UserID: "u1", Role: "admin"})
	if err == nil {
		t.Fatal("role admin was accepted")
	}
	if !strings.Contains(err.Error(), "--role") || !strings.Contains(err.Error(), "team_manager") {
		t.Errorf("error %q should name the flag and the allowed roles", err)
	}
}
