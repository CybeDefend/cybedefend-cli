// File: pkg/api/severity_gate_test.go

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// flatFinding is the shape the container endpoint returns: no "base" wrapper.
func flatFinding(id, severity, state string) string {
	return fmt.Sprintf(`{"id":%q,"currentSeverity":%q,"currentState":%q,"currentPriority":"urgent","vulnerabilityIdentifier":"CVE-2024-0001"}`,
		id, severity, state)
}

// nestedFinding is the shape every other endpoint returns: everything the gate
// reads lives under "base", not at the top level.
func nestedFinding(id, severity, state string) string {
	return fmt.Sprintf(`{"dataFlowItems":[],"base":{"id":%q,"currentSeverity":%q,"currentState":%q,"currentPriority":"urgent","path":"app.py","vulnerability":{"name":"SQL Injection"}}}`,
		id, severity, state)
}

// gateServer records which scan types and branches were asked for, and serves a
// fixed set of findings per scan type.
type gateServer struct {
	perType  map[string][]string
	branches map[string]bool
	asked    map[string]bool
}

func (g *gateServer) start(t *testing.T) *Client {
	t.Helper()
	g.branches = map[string]bool{}
	g.asked = map[string]bool{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":600}`)
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		scanType := parts[len(parts)-1]
		g.asked[scanType] = true
		g.branches[r.URL.Query().Get("branch")] = true

		findings := g.perType[scanType]
		fmt.Fprintf(w, `{"projectId":"p1","page":1,"total":%d,"totalPages":1,"vulnerabilities":[%s]}`,
			len(findings), strings.Join(findings, ","))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "pat", srv.URL, "cid", srv.URL)
}

// The gate used to read `currentSeverity` at the top level of a response that
// nests it under `base`. Every finding was skipped, the counts came back empty,
// and --break-on-severity reported a clean build for a project whose policy
// evaluation was blocking. A gate that fails open is worse than no gate.
func TestCountVulnerabilitiesBySeverity_ReadsTheNestedShape(t *testing.T) {
	g := &gateServer{perType: map[string][]string{
		"sast": {
			nestedFinding("v1", "critical", "to_verify"),
			nestedFinding("v2", "critical", "confirmed"),
			nestedFinding("v3", "high", "to_verify"),
		},
	}}
	client := g.start(t)

	counts, err := client.CountVulnerabilitiesBySeverity("p1", "main", []string{"critical"})
	if err != nil {
		t.Fatalf("CountVulnerabilitiesBySeverity returned %v", err)
	}
	if counts["critical"] != 2 {
		t.Errorf("critical = %d, want 2 — the gate is not reading the nested `base` object", counts["critical"])
	}
	if counts["high"] != 0 {
		t.Errorf("high = %d, want 0: only the requested severities are counted", counts["high"])
	}
}

// A finding somebody has already ruled on must not block a build.
func TestCountVulnerabilitiesBySeverity_SkipsSettledFindings(t *testing.T) {
	g := &gateServer{perType: map[string][]string{
		"sast": {
			nestedFinding("v1", "critical", "resolved"),
			nestedFinding("v2", "critical", "not_exploitable"),
			nestedFinding("v3", "critical", "ignored"),
			nestedFinding("v4", "critical", "to_verify"),
		},
	}}
	client := g.start(t)

	counts, err := client.CountVulnerabilitiesBySeverity("p1", "main", []string{"critical"})
	if err != nil {
		t.Fatalf("CountVulnerabilitiesBySeverity returned %v", err)
	}
	if counts["critical"] != 1 {
		t.Errorf("critical = %d, want 1: resolved, not_exploitable and ignored do not gate a build", counts["critical"])
	}
}

// The gate queried "sast" and nothing else, so a critical CVE in a dependency
// never blocked a build.
func TestCountVulnerabilitiesBySeverity_CoversEveryScanType(t *testing.T) {
	g := &gateServer{perType: map[string][]string{
		"sca":       {nestedFinding("dep1", "critical", "to_verify")},
		"secret":    {nestedFinding("sec1", "critical", "confirmed")},
		"iac":       {nestedFinding("iac1", "critical", "to_verify")},
		"container": {flatFinding("img1", "critical", "to_verify")},
	}}
	client := g.start(t)

	counts, err := client.CountVulnerabilitiesBySeverity("p1", "main", []string{"critical"})
	if err != nil {
		t.Fatalf("CountVulnerabilitiesBySeverity returned %v", err)
	}
	// container is counted through its own flat shape, the other three through
	// the nested one: the gate has to handle both.
	if counts["critical"] != 4 {
		t.Errorf("critical = %d, want 4 across sca, secret, iac and container", counts["critical"])
	}
	for _, scanType := range ValidScanTypes {
		if scanType == "all" {
			continue
		}
		if !g.asked[scanType] {
			t.Errorf("the gate never queried %q", scanType)
		}
	}
	if g.asked["all"] {
		t.Error(`the gate must not query the "all" pseudo-type`)
	}
}

// The count is about the branch that was just scanned, not about every branch
// the project has ever had.
func TestCountVulnerabilitiesBySeverity_FiltersOnTheScannedBranch(t *testing.T) {
	g := &gateServer{perType: map[string][]string{"sast": {nestedFinding("v1", "low", "to_verify")}}}
	client := g.start(t)

	if _, err := client.CountVulnerabilitiesBySeverity("p1", "release/2.0", []string{"low"}); err != nil {
		t.Fatalf("CountVulnerabilitiesBySeverity returned %v", err)
	}
	if !g.branches["release/2.0"] {
		t.Errorf("the branch was not passed to the API, branches seen: %v", g.branches)
	}
}

// Only the first page used to be read, so the counts were a truncation of the
// result set rather than the result set.
func TestCountVulnerabilitiesBySeverity_WalksEveryPage(t *testing.T) {
	var pagesServed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":600}`)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/sast") {
			fmt.Fprint(w, `{"projectId":"p1","page":1,"total":0,"totalPages":1,"vulnerabilities":[]}`)
			return
		}
		page := r.URL.Query().Get("pageNumber")
		pagesServed = append(pagesServed, page)
		fmt.Fprintf(w, `{"projectId":"p1","page":%s,"total":6,"totalPages":3,"vulnerabilities":[%s,%s]}`,
			page, nestedFinding("a"+page, "critical", "to_verify"), nestedFinding("b"+page, "critical", "to_verify"))
	}))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "pat", srv.URL, "cid", srv.URL)
	counts, err := client.CountVulnerabilitiesBySeverity("p1", "main", []string{"critical"})
	if err != nil {
		t.Fatalf("CountVulnerabilitiesBySeverity returned %v", err)
	}
	if counts["critical"] != 6 {
		t.Errorf("critical = %d, want 6 (2 per page over 3 pages), pages served: %v", counts["critical"], pagesServed)
	}
	if len(pagesServed) != 3 {
		t.Errorf("served pages %v, want all three walked", pagesServed)
	}
}

// A scan type the plan does not cover answers 403. That must not abandon the
// gate for the types it does cover — nor silently pass one that errors for any
// other reason.
func TestCountVulnerabilitiesBySeverity_ForbiddenTypeIsSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":600}`)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/container") {
			http.Error(w, `{"statusCode":403,"message":"not in plan"}`, http.StatusForbidden)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/sast") {
			fmt.Fprintf(w, `{"projectId":"p1","page":1,"total":1,"totalPages":1,"vulnerabilities":[%s]}`,
				nestedFinding("v1", "critical", "to_verify"))
			return
		}
		fmt.Fprint(w, `{"projectId":"p1","page":1,"total":0,"totalPages":1,"vulnerabilities":[]}`)
	}))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "pat", srv.URL, "cid", srv.URL)
	counts, err := client.CountVulnerabilitiesBySeverity("p1", "main", []string{"critical"})
	if err != nil {
		t.Fatalf("a forbidden scan type must not fail the whole gate, got %v", err)
	}
	if counts["critical"] != 1 {
		t.Errorf("critical = %d, want the sast finding to still be counted", counts["critical"])
	}
}

// The severity gate reads CurrentState, and the `results` output exports it so
// consumers can tell which triage state each finding is in (DEV-67).
func TestVulnerability_CurrentStateIsDecodedAndSerialised(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":600}`)
			return
		}
		fmt.Fprintf(w, `{"projectId":"p1","page":1,"total":1,"totalPages":1,"vulnerabilities":[%s]}`,
			nestedFinding("v1", "critical", "to_verify"))
	}))
	t.Cleanup(srv.Close)

	client := NewClient(srv.URL, "pat", srv.URL, "cid", srv.URL)
	results, err := client.GetResults("p1", "sast", 1, 20, "", nil)
	if err != nil {
		t.Fatalf("GetResults returned %v", err)
	}
	v := results.Vulnerabilities[0]
	if v.CurrentState != "to_verify" {
		t.Fatalf("CurrentState = %q, want it decoded for the gate", v.CurrentState)
	}

	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshalling returned %v", err)
	}
	if !strings.Contains(string(encoded), `"currentState":"to_verify"`) {
		t.Errorf("currentState must be part of the results output, got %s", encoded)
	}
}
