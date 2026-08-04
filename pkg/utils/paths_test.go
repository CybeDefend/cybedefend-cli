// File: pkg/utils/paths_test.go

package utils

import (
	"strings"
	"testing"
)

func TestSanitizeServerFilenameAcceptsPlainNames(t *testing.T) {
	cases := []string{
		"batch-owasp.pdf",
		"report_2024-01-01.json",
		"CybeDefend Report (final).html",
		".hidden-report.json",
	}

	for _, name := range cases {
		got, err := SanitizeServerFilename(name)
		if err != nil {
			t.Fatalf("SanitizeServerFilename(%q) returned error %v, want nil", name, err)
		}
		if got != name {
			t.Fatalf("SanitizeServerFilename(%q) = %q, want %q", name, got, name)
		}
	}
}

func TestSanitizeServerFilenameStripsDirectoryComponents(t *testing.T) {
	cases := map[string]string{
		"reports/batch-owasp.pdf":      "batch-owasp.pdf",
		"./batch-owasp.pdf":            "batch-owasp.pdf",
		"a/b/c/report.json":            "report.json",
		`windows\subdir\report.json`:   "report.json",
		"/tmp/absolute/report.json":    "report.json",
		`C:\Users\victim\report.json`:  "report.json",
		"../../../../etc/report.json":  "report.json",
		`..\..\..\Windows\report.json`: "report.json",
	}

	for in, want := range cases {
		got, err := SanitizeServerFilename(in)
		if err != nil {
			t.Fatalf("SanitizeServerFilename(%q) returned error %v, want nil", in, err)
		}
		if got != want {
			t.Fatalf("SanitizeServerFilename(%q) = %q, want %q", in, got, want)
		}
	}
}

// The concrete attack from the audit: a malicious or redirected API answers the
// batch-report call with {"filename": "../../../../.ssh/authorized_keys"} and the
// CLI used to MkdirAll the parent and write server-controlled bytes there.
func TestSanitizeServerFilenameDefeatsTraversalToSSHKeys(t *testing.T) {
	got, err := SanitizeServerFilename("../../../../.ssh/authorized_keys")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "authorized_keys" {
		t.Fatalf("got %q, want %q", got, "authorized_keys")
	}
	if strings.ContainsAny(got, `/\`) {
		t.Fatalf("sanitized name %q still contains a path separator", got)
	}
}

func TestSanitizeServerFilenameRejectsNamesWithNoUsableBase(t *testing.T) {
	cases := []string{
		"",
		"   ",
		".",
		"..",
		"/",
		"./",
		"../",
		"../..",
		`\`,
		"/tmp/",
		"a/b/..",
		"report\x00.json",
		"\treport.json\n",
	}

	for _, name := range cases {
		got, err := SanitizeServerFilename(name)
		if err == nil {
			t.Fatalf("SanitizeServerFilename(%q) = %q, want an error", name, got)
		}
	}
}

func TestSanitizeServerFilenameIsIdempotent(t *testing.T) {
	once, err := SanitizeServerFilename("../../evil/report.pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	twice, err := SanitizeServerFilename(once)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if once != twice {
		t.Fatalf("not idempotent: %q then %q", once, twice)
	}
}
