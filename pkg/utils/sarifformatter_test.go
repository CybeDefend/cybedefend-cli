package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// runResults decodes runs[0].results, keeping the distinction that matters
// here: a JSON null decodes to a nil slice, an empty JSON array does not.
func runResults(t *testing.T, path string) []any {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the generated report: %v", err)
	}

	var doc struct {
		Runs []struct {
			Results []any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the generated report is not valid JSON: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected exactly one run, got %d", len(doc.Runs))
	}
	return doc.Runs[0].Results
}

// A scan with no findings is the steady state of a healthy repository, and it
// is the one case that used to produce an unusable report: `results` was a nil
// slice, which encoding/json writes as `null`. The SARIF 2.1.0 schema types
// run.results as an array, so strict consumers — GitHub code scanning among
// them — reject the file.
func TestConvertToSARIF_EmptyReportEmitsAnEmptyResultsArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.sarif")

	if err := ConvertToSARIF(VulnerabilityReport{}, path); err != nil {
		t.Fatalf("ConvertToSARIF returned %v", err)
	}

	results := runResults(t, path)
	if results == nil {
		t.Fatal("runs[0].results is null; the SARIF schema requires an array, so the report is rejected on upload")
	}
	if len(results) != 0 {
		t.Fatalf("expected no results, got %d", len(results))
	}
}

// Regression guard for the change above: preallocating the slice must not
// change what a report with findings produces.
func TestConvertToSARIF_MapsEachVulnerabilityToAResult(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.sarif")

	report := VulnerabilityReport{
		Vulnerabilities: []Vulnerability{
			{
				ID:                  "id-1",
				Name:                "SQL Injection",
				Description:         "Unsanitised input reaches a query",
				Severity:            "CRITICAL",
				Path:                "app/db.go",
				VulnerableStartLine: 42,
				VulnerableEndLine:   43,
			},
			{
				ID:       "id-2",
				Severity: "LOW",
				Path:     "app/util.go",
			},
		},
	}

	if err := ConvertToSARIF(report, path); err != nil {
		t.Fatalf("ConvertToSARIF returned %v", err)
	}

	results := runResults(t, path)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	first, ok := results[0].(map[string]any)
	if !ok {
		t.Fatalf("expected an object, got %T", results[0])
	}
	if got := first["ruleId"]; got != "SQL Injection" {
		t.Errorf("ruleId = %v, want the vulnerability name", got)
	}
	if got := first["level"]; got != "error" {
		t.Errorf("level = %v, want error for CRITICAL", got)
	}

	// An unnamed finding falls back to its instance ID rather than an empty rule.
	second := results[1].(map[string]any)
	if got := second["ruleId"]; got != "id-2" {
		t.Errorf("ruleId = %v, want the instance ID fallback", got)
	}
}
