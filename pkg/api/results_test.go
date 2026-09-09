package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newResultsTestClient returns a Client pointed at a test server that answers
// the token exchange and serves the given JSON for every other route.
func newResultsTestClient(t *testing.T, resultsJSON string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oidc/token" {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":600}`))
			return
		}
		_, _ = w.Write([]byte(resultsJSON))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-pat", srv.URL, "client-id", srv.URL)
}

func TestGetResults_SastExposesScoresAndPriority(t *testing.T) {
	client := newResultsTestClient(t, `{
		"projectId": "p1", "projectName": "proj", "page": 1, "total": 1, "totalPages": 1,
		"vulnerabilities": [{
			"base": {
				"id": "v1",
				"currentSeverity": "critical",
				"currentPriority": "urgent",
				"language": "go",
				"path": "main.go",
				"vulnerableStartLine": 10,
				"vulnerableEndLine": 12,
				"branch": "main",
				"scoringSource": "static",
				"cvss4Vector": "CVSS:4.0/AV:N/AC:H",
				"cvss4BaseScore": 9.3,
				"cvss4EnvironmentalScore": 2.3,
				"cvss4EnvironmentalVector": "CVSS:4.0/AV:N/AC:H/CR:H",
				"epssScore": 0.013,
				"epssPercentile": 0.87,
				"exploitabilityScore": 0.35,
				"exploitabilityVerdict": "theoretical",
				"priorityScore": 20.8,
				"vulnerability": {
					"name": "SQL Injection",
					"severity": "CRITICAL",
					"cwe": ["CWE-89"]
				}
			}
		}]
	}`)

	res, err := client.GetResults("p1", "sast", 1, 20, "", nil)
	if err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	if len(res.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(res.Vulnerabilities))
	}
	v := res.Vulnerabilities[0]

	if v.CurrentSeverity != "critical" {
		t.Errorf("CurrentSeverity = %q, want critical", v.CurrentSeverity)
	}
	if v.CurrentPriority != "urgent" {
		t.Errorf("CurrentPriority = %q, want urgent", v.CurrentPriority)
	}
	if v.CVE != "" {
		t.Errorf("CVE = %q, want empty for SAST", v.CVE)
	}
	s := v.Scores
	if s == nil {
		t.Fatal("Scores is nil, want populated")
	}
	if s.PriorityScore == nil || *s.PriorityScore != 20.8 {
		t.Errorf("PriorityScore = %v, want 20.8", s.PriorityScore)
	}
	if s.Cvss4BaseScore == nil || *s.Cvss4BaseScore != 9.3 {
		t.Errorf("Cvss4BaseScore = %v, want 9.3", s.Cvss4BaseScore)
	}
	if s.Cvss4EnvironmentalScore == nil || *s.Cvss4EnvironmentalScore != 2.3 {
		t.Errorf("Cvss4EnvironmentalScore = %v, want 2.3", s.Cvss4EnvironmentalScore)
	}
	if s.Cvss4Vector != "CVSS:4.0/AV:N/AC:H" {
		t.Errorf("Cvss4Vector = %q", s.Cvss4Vector)
	}
	if s.Cvss4EnvironmentalVector != "CVSS:4.0/AV:N/AC:H/CR:H" {
		t.Errorf("Cvss4EnvironmentalVector = %q", s.Cvss4EnvironmentalVector)
	}
	if s.EpssScore == nil || *s.EpssScore != 0.013 {
		t.Errorf("EpssScore = %v, want 0.013", s.EpssScore)
	}
	if s.EpssPercentile == nil || *s.EpssPercentile != 0.87 {
		t.Errorf("EpssPercentile = %v, want 0.87", s.EpssPercentile)
	}
	if s.ExploitabilityScore == nil || *s.ExploitabilityScore != 0.35 {
		t.Errorf("ExploitabilityScore = %v, want 0.35", s.ExploitabilityScore)
	}
	if s.ExploitabilityVerdict != "theoretical" {
		t.Errorf("ExploitabilityVerdict = %q", s.ExploitabilityVerdict)
	}
	if s.ScoringSource != "static" {
		t.Errorf("ScoringSource = %q", s.ScoringSource)
	}
	b := s.Cvss4Breakdown
	if b == nil || len(b.Base) == 0 || b.Base[0].Metrics[0].Label != "Network" {
		t.Fatalf("Cvss4Breakdown not decoded from the vectors: %+v", b)
	}
	if len(b.Environmental) != 1 || b.Environmental[0].Metric != "CR" || b.Environmental[0].Label != "High" {
		t.Errorf("Environmental = %+v, want CR High from the environmental vector", b.Environmental)
	}
}

func TestGetResults_ScaResolvesCveFromMetadata(t *testing.T) {
	client := newResultsTestClient(t, `{
		"projectId": "p1", "projectName": "proj", "page": 1, "total": 2, "totalPages": 1,
		"vulnerabilities": [
			{
				"base": {
					"id": "sca1",
					"currentSeverity": "medium",
					"currentPriority": "low",
					"priorityScore": 12.5,
					"epssScore": 0.002,
					"epssPercentile": 0.41
				},
				"metadata": {
					"ghsaId": "GHSA-xxxx",
					"cve": "CVE-2024-47764",
					"summary": "cookie parsing flaw",
					"cwes": [{"cweId": "CWE-74"}]
				},
				"library": {
					"packageName": "cookie",
					"packageVersion": "0.3.1",
					"ecosystem": "npm"
				}
			},
			{
				"base": {"id": "sca2", "currentSeverity": "low"},
				"metadata": {
					"ghsaId": "GHSA-yyyy",
					"summary": "other flaw",
					"aliases": [{"alias": "PYSEC-1"}, {"alias": "CVE-2020-15366"}]
				}
			}
		]
	}`)

	res, err := client.GetResults("p1", "sca", 1, 20, "", nil)
	if err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	if len(res.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(res.Vulnerabilities))
	}

	if got := res.Vulnerabilities[0].CVE; got != "CVE-2024-47764" {
		t.Errorf("CVE from metadata.cve = %q, want CVE-2024-47764", got)
	}
	if s := res.Vulnerabilities[0].Scores; s == nil || s.PriorityScore == nil || *s.PriorityScore != 12.5 {
		t.Errorf("SCA Scores.PriorityScore not mapped: %+v", s)
	}

	if got := res.Vulnerabilities[1].CVE; got != "CVE-2020-15366" {
		t.Errorf("CVE from aliases fallback = %q, want CVE-2020-15366", got)
	}
}

func TestGetResults_ScoresOmittedWhenAbsent(t *testing.T) {
	client := newResultsTestClient(t, `{
		"projectId": "p1", "projectName": "proj", "page": 1, "total": 1, "totalPages": 1,
		"vulnerabilities": [{
			"base": {
				"id": "v1",
				"scoringSource": "static",
				"vulnerability": {"name": "Hardcoded secret", "severity": "HIGH"}
			}
		}]
	}`)

	res, err := client.GetResults("p1", "secret", 1, 20, "", nil)
	if err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	v := res.Vulnerabilities[0]
	if v.Scores != nil {
		t.Errorf("Scores = %+v, want nil when the API sends no score (scoringSource alone is a default, not a score)", v.Scores)
	}

	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, absent := range []string{`"scores"`, `"cve"`, `"currentPriority"`} {
		if strings.Contains(string(out), absent) {
			t.Errorf("output JSON should omit %s when empty: %s", absent, out)
		}
	}
}

func TestGetResults_ContainerParsesFlatShape(t *testing.T) {
	client := newResultsTestClient(t, `{
		"projectId": "p1", "projectName": "proj", "page": 1, "total": 1, "totalPages": 1,
		"vulnerabilities": [{
			"id": "c1",
			"vulnerabilityIdentifier": "CVE-2023-45853",
			"currentState": "to_verify",
			"currentSeverity": "critical",
			"currentPriority": "urgent",
			"fixedVersion": "1:1.2.13.dfsg-2",
			"branch": "main",
			"scoringSource": "static",
			"cvss4BaseScore": 9.8,
			"epssScore": 0.7,
			"epssPercentile": 0.99,
			"priorityScore": 88.4,
			"package": {"name": "zlib1g", "version": "1:1.2.13.dfsg-1"},
			"vuln": {
				"vulnerabilityId": "CVE-2023-45853",
				"title": "zlib: integer overflow in zipOpenNewFileInZip4_64",
				"severity": "CRITICAL",
				"type": "",
				"class": "os-pkgs",
				"cweIds": ["CWE-190"]
			}
		}]
	}`)

	res, err := client.GetResults("p1", "container", 1, 20, "", nil)
	if err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	if len(res.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(res.Vulnerabilities))
	}
	v := res.Vulnerabilities[0]

	if v.ID != "c1" {
		t.Errorf("ID = %q, want c1", v.ID)
	}
	if v.CVE != "CVE-2023-45853" {
		t.Errorf("CVE = %q, want CVE-2023-45853", v.CVE)
	}
	if v.Details.Name != "zlib: integer overflow in zipOpenNewFileInZip4_64" {
		t.Errorf("Details.Name = %q", v.Details.Name)
	}
	if v.Details.Severity != "CRITICAL" {
		t.Errorf("Details.Severity = %q, want CRITICAL", v.Details.Severity)
	}
	if len(v.Details.CWE) != 1 || v.Details.CWE[0] != "CWE-190" {
		t.Errorf("Details.CWE = %v, want [CWE-190]", v.Details.CWE)
	}
	if v.Path != "zlib1g@1:1.2.13.dfsg-1" {
		t.Errorf("Path = %q, want zlib1g@1:1.2.13.dfsg-1", v.Path)
	}
	if v.Language != "os-pkgs" {
		t.Errorf("Language = %q, want os-pkgs (class fallback when type is empty)", v.Language)
	}
	if v.CurrentPriority != "urgent" {
		t.Errorf("CurrentPriority = %q, want urgent", v.CurrentPriority)
	}
	if !strings.Contains(v.Details.HowToPrevent, "1:1.2.13.dfsg-2") {
		t.Errorf("HowToPrevent = %q, want mention of the fixed version", v.Details.HowToPrevent)
	}
	s := v.Scores
	if s == nil {
		t.Fatal("Scores is nil, want populated")
	}
	if s.Cvss4BaseScore == nil || *s.Cvss4BaseScore != 9.8 {
		t.Errorf("Cvss4BaseScore = %v, want 9.8", s.Cvss4BaseScore)
	}
	if s.PriorityScore == nil || *s.PriorityScore != 88.4 {
		t.Errorf("PriorityScore = %v, want 88.4", s.PriorityScore)
	}
}

// newQueryCapturingClient returns a Client whose server records the query of
// the last non-token request and answers it with an empty results page.
func newQueryCapturingClient(t *testing.T) (*Client, *url.Values) {
	t.Helper()
	captured := &url.Values{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oidc/token" {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":600}`))
			return
		}
		*captured = r.URL.Query()
		_, _ = w.Write([]byte(`{"projectId":"p1","projectName":"proj","page":1,"total":0,"totalPages":0,"vulnerabilities":[],"groupedVulnerabilities":[]}`))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-pat", srv.URL, "client-id", srv.URL), captured
}

// The gateway's query parser keeps `status[]` verbatim as a key named
// "status[]", so a bracketed array never reaches the `status` filter and the
// API answers with every state (ignored, resolved...). Filters must use the
// repeated-key form the gateway actually reads.
func TestGetResults_SendsRepeatedFilterParams(t *testing.T) {
	client, q := newQueryCapturingClient(t)
	if _, err := client.GetResults("p1", "sast", 1, 20, "", nil); err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	for _, bracketed := range []string{"status[]", "severity[]", "priority[]"} {
		if _, ok := (*q)[bracketed]; ok {
			t.Errorf("query must not carry the bracketed key %q: %v", bracketed, *q)
		}
	}
	if got := (*q)["status"]; !equalStrings(got, DefaultResultStatuses) {
		t.Errorf("status = %v, want %v", got, DefaultResultStatuses)
	}
	// No severity / priority restriction: the API only accepts the four rated
	// levels as filter values, so sending them all would silently drop the
	// findings without a rating (SCA advisories without a CVSS score).
	for _, key := range []string{"severity", "priority"} {
		if _, ok := (*q)[key]; ok {
			t.Errorf("query must not restrict %q: %v", key, *q)
		}
	}
}

func TestGetResults_HonoursRequestedStatuses(t *testing.T) {
	client, q := newQueryCapturingClient(t)
	if _, err := client.GetResults("p1", "sca", 1, 20, "", []string{"ignored", "resolved"}); err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	if got := (*q)["status"]; !equalStrings(got, []string{"ignored", "resolved"}) {
		t.Errorf("status = %v, want [ignored resolved]", got)
	}
}

func TestGetGroupedResults_SendsRepeatedFilterParams(t *testing.T) {
	client, q := newQueryCapturingClient(t)
	if _, err := client.GetGroupedResults("p1", "sast", 1, 50, "", nil); err != nil {
		t.Fatalf("GetGroupedResults: %v", err)
	}
	for _, bracketed := range []string{"statusFilter[]", "severityFilter[]", "priorityFilter[]"} {
		if _, ok := (*q)[bracketed]; ok {
			t.Errorf("query must not carry the bracketed key %q: %v", bracketed, *q)
		}
	}
	if got := (*q)["statusFilter"]; !equalStrings(got, DefaultResultStatuses) {
		t.Errorf("statusFilter = %v, want %v", got, DefaultResultStatuses)
	}
	for _, key := range []string{"severityFilter", "priorityFilter"} {
		if _, ok := (*q)[key]; ok {
			t.Errorf("query must not restrict %q: %v", key, *q)
		}
	}
}

func TestGetGroupedResults_HonoursRequestedStatuses(t *testing.T) {
	client, q := newQueryCapturingClient(t)
	if _, err := client.GetGroupedResults("p1", "iac", 1, 50, "", []string{"ignored"}); err != nil {
		t.Fatalf("GetGroupedResults: %v", err)
	}
	if got := (*q)["statusFilter"]; !equalStrings(got, []string{"ignored"}) {
		t.Errorf("statusFilter = %v, want [ignored]", got)
	}
}

// The flat output must let consumers see the state of each finding, so a
// custom --status export (e.g. ignored) is self-describing.
func TestVulnerability_SerialisesCurrentState(t *testing.T) {
	raw, err := json.Marshal(Vulnerability{ID: "v1", CurrentState: "ignored"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"currentState":"ignored"`) {
		t.Errorf("currentState missing from JSON: %s", raw)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
