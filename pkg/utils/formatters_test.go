package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cybedefend-cli/pkg/cvss"
)

func scoredVulnerability() Vulnerability {
	pr := 20.8
	base := 9.3
	env := 2.3
	epss := 0.013
	pctl := 0.87
	return Vulnerability{
		ID:                       "v1",
		Name:                     "zlib: integer overflow",
		Severity:                 "CRITICAL",
		Language:                 "debian",
		Path:                     "zlib1g@1:1.2.13",
		VulnerableStartLine:      1,
		CWE:                      []string{"CWE-190"},
		CVE:                      "CVE-2023-45853",
		Priority:                 "urgent",
		PriorityScore:            &pr,
		Cvss4BaseScore:           &base,
		Cvss4EnvironmentalScore:  &env,
		Cvss4Vector:              "CVSS:4.0/AV:N/AC:H",
		Cvss4EnvironmentalVector: "CVSS:4.0/AV:N/AC:H/CR:H",
		Cvss4Breakdown:           cvss.ParseV4("CVSS:4.0/AV:N/AC:H", "CVSS:4.0/AV:N/AC:H/CR:H"),
		EpssScore:                &epss,
		EpssPercentile:           &pctl,
		ExploitabilityVerdict:    "theoretical",
	}
}

func reportWith(v Vulnerability) VulnerabilityReport {
	return VulnerabilityReport{
		ProjectName:       "proj",
		ProjectID:         "p1",
		Total:             1,
		Page:              1,
		TotalPages:        1,
		Vulnerabilities:   []Vulnerability{v},
		VulnerabilityType: "container",
	}
}

func TestRenderMarkdownReport_IncludesCveAndScores(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.md")
	if err := RenderMarkdownReport(reportWith(scoredVulnerability()), out); err != nil {
		t.Fatalf("RenderMarkdownReport: %v", err)
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	md := string(content)

	for _, want := range []string{
		"[CVE-2023-45853](https://nvd.nist.gov/vuln/detail/CVE-2023-45853)",
		"**Priority:** `URGENT` (score 20.8/100)",
		"**CVSS 4.0 Base:** 9.3 (`CVSS:4.0/AV:N/AC:H`)",
		"**CVSS 4.0 Environmental:** 2.3 (`CVSS:4.0/AV:N/AC:H/CR:H`)",
		"**EPSS:** 1.3% (percentile 87.0%)",
		"**Exploitability:** `theoretical`",
		"| Exploitability | `AV:N` Attack Vector | Network |",
		"| Exploitability | `AC:H` Attack Complexity | High |",
		"| Environmental | `CR:H` Confidentiality Requirement | High |",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown report missing %q\n---\n%s", want, md)
		}
	}
}

func TestRenderMarkdownReport_OmitsScoreLinesWhenAbsent(t *testing.T) {
	v := Vulnerability{Name: "Hardcoded secret", Severity: "HIGH", Path: "config.yaml"}
	out := filepath.Join(t.TempDir(), "report.md")
	if err := RenderMarkdownReport(reportWith(v), out); err != nil {
		t.Fatalf("RenderMarkdownReport: %v", err)
	}
	content, _ := os.ReadFile(out)
	for _, absent := range []string{"**CVE:**", "**Priority:**", "**CVSS", "**EPSS:**", "**Exploitability:**"} {
		if strings.Contains(string(content), absent) {
			t.Errorf("markdown report should omit %q for an unscored vulnerability", absent)
		}
	}
}

func TestRenderMarkdownReport_MalformedCveIsNotLinked(t *testing.T) {
	v := scoredVulnerability()
	v.CVE = "CVE-BAD)(x"
	out := filepath.Join(t.TempDir(), "report.md")
	if err := RenderMarkdownReport(reportWith(v), out); err != nil {
		t.Fatalf("RenderMarkdownReport: %v", err)
	}
	content, _ := os.ReadFile(out)
	md := string(content)
	if strings.Contains(md, "nvd.nist.gov") {
		t.Errorf("malformed CVE must not produce an NVD link:\n%s", md)
	}
	if !strings.Contains(md, "**CVE:** `CVE-BAD)(x`") {
		t.Errorf("malformed CVE should still be rendered as plain code:\n%s", md)
	}
}

func TestConvertToSARIF_AttachesPropertyBag(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	if err := ConvertToSARIF(reportWith(scoredVulnerability()), out); err != nil {
		t.Fatalf("ConvertToSARIF: %v", err)
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	var sarif SarifReport
	if err := json.Unmarshal(content, &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	props := sarif.Runs[0].Results[0].Properties
	if props == nil {
		t.Fatal("expected a property bag on the SARIF result")
	}
	if props["cve"] != "CVE-2023-45853" {
		t.Errorf("properties.cve = %v", props["cve"])
	}
	if props["priority"] != "urgent" {
		t.Errorf("properties.priority = %v", props["priority"])
	}
	if props["priorityScore"] != 20.8 {
		t.Errorf("properties.priorityScore = %v", props["priorityScore"])
	}
	// Environmental score wins over base for the GitHub convention.
	if props["security-severity"] != "2.3" {
		t.Errorf("properties.security-severity = %v, want \"2.3\"", props["security-severity"])
	}
	breakdown, ok := props["cvss4Breakdown"].(map[string]any)
	if !ok || breakdown["base"] == nil {
		t.Errorf("properties.cvss4Breakdown missing or malformed: %v", props["cvss4Breakdown"])
	}
}

func TestConvertToSARIF_NoPropertyBagWhenUnscored(t *testing.T) {
	v := Vulnerability{Name: "Hardcoded secret", Severity: "HIGH", Path: "config.yaml"}
	out := filepath.Join(t.TempDir(), "report.sarif")
	if err := ConvertToSARIF(reportWith(v), out); err != nil {
		t.Fatalf("ConvertToSARIF: %v", err)
	}
	content, _ := os.ReadFile(out)
	var sarif SarifReport
	if err := json.Unmarshal(content, &sarif); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if props := sarif.Runs[0].Results[0].Properties; props != nil {
		t.Errorf("expected no property bag, got %v", props)
	}
}

func TestRenderHTMLReport_RendersScoresAndCve(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.html")
	if err := RenderHTMLReport(reportWith(scoredVulnerability()), out); err != nil {
		t.Fatalf("RenderHTMLReport: %v", err)
	}
	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(content)
	for _, want := range []string{
		"Risk Scores",
		"CVE-2023-45853",
		"20.8/100",
		"9.3",
		"2.3",
		"CVSS:4.0/AV:N/AC:H/CR:H",
		"theoretical",
		"Attack Vector",
		"Confidentiality Requirement",
		"Network",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}
