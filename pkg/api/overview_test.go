package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newOverviewTestClient returns a Client pointed at a test server that answers
// the token exchange and serves the given JSON for every other route.
func newOverviewTestClient(t *testing.T, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oidc/token" {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":600}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, "test-pat", srv.URL, "client-id", srv.URL)
}

// The API reports risk under "cyberRisk". Reading a flat riskScore/riskLevel
// pair the API never sends left every project scored 0 with no level.
func TestGetProjectOverview_ReadsCyberRisk(t *testing.T) {
	client := newOverviewTestClient(t, `{
		"totalBySeverity": [{"severity": "critical", "count": 8}],
		"cyberRisk": {"score": 3684, "level": "critical", "computedAt": "2026-09-10T09:07:57.099Z"}
	}`)

	overview, err := client.GetProjectOverview("p1", nil)
	if err != nil {
		t.Fatalf("GetProjectOverview returned an error: %v", err)
	}

	if overview.RiskScore == nil {
		t.Fatal("RiskScore is nil, want 3684")
	}
	if *overview.RiskScore != 3684 {
		t.Errorf("RiskScore = %v, want 3684", *overview.RiskScore)
	}
	if overview.RiskLevel != "critical" {
		t.Errorf("RiskLevel = %q, want %q", overview.RiskLevel, "critical")
	}
}

// A genuine zero score must stay distinguishable from "not computed".
func TestGetProjectOverview_KeepsZeroScore(t *testing.T) {
	client := newOverviewTestClient(t, `{"cyberRisk": {"score": 0, "level": "low"}}`)

	overview, err := client.GetProjectOverview("p1", nil)
	if err != nil {
		t.Fatalf("GetProjectOverview returned an error: %v", err)
	}

	if overview.RiskScore == nil {
		t.Fatal("RiskScore is nil, want a present 0")
	}
	if *overview.RiskScore != 0 {
		t.Errorf("RiskScore = %v, want 0", *overview.RiskScore)
	}
}

// With no risk block at all the fields must disappear from the output rather
// than assert a score of 0 the API never reported.
func TestGetProjectOverview_OmitsAbsentRisk(t *testing.T) {
	client := newOverviewTestClient(t, `{"totalBySeverity": [{"severity": "low", "count": 2}]}`)

	overview, err := client.GetProjectOverview("p1", nil)
	if err != nil {
		t.Fatalf("GetProjectOverview returned an error: %v", err)
	}

	if overview.RiskScore != nil {
		t.Errorf("RiskScore = %v, want nil", *overview.RiskScore)
	}

	encoded, err := json.Marshal(overview)
	if err != nil {
		t.Fatalf("marshalling the overview failed: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("re-reading the encoded overview failed: %v", err)
	}
	if _, present := fields["riskScore"]; present {
		t.Error("riskScore is present in the output, want it omitted")
	}
	if _, present := fields["riskLevel"]; present {
		t.Error("riskLevel is present in the output, want it omitted")
	}
}

// The flat pair still wins if a future API sends it without a cyberRisk block.
func TestGetProjectOverview_AcceptsFlatRisk(t *testing.T) {
	client := newOverviewTestClient(t, `{"riskScore": 42.5, "riskLevel": "medium"}`)

	overview, err := client.GetProjectOverview("p1", nil)
	if err != nil {
		t.Fatalf("GetProjectOverview returned an error: %v", err)
	}

	if overview.RiskScore == nil {
		t.Fatal("RiskScore is nil, want 42.5")
	}
	if *overview.RiskScore != 42.5 {
		t.Errorf("RiskScore = %v, want 42.5", *overview.RiskScore)
	}
	if overview.RiskLevel != "medium" {
		t.Errorf("RiskLevel = %q, want %q", overview.RiskLevel, "medium")
	}
}

// The organization endpoint sends no risk figure, so the CLI must not invent one.
func TestGetOrgOverview_OmitsAbsentRisk(t *testing.T) {
	client := newOverviewTestClient(t, `{"organizationId": "o1", "totalProjects": 5}`)

	overview, err := client.GetOrgOverview("o1", nil)
	if err != nil {
		t.Fatalf("GetOrgOverview returned an error: %v", err)
	}

	if overview.RiskScore != nil {
		t.Errorf("RiskScore = %v, want nil", *overview.RiskScore)
	}
	if overview.TotalProjects != 5 {
		t.Errorf("TotalProjects = %d, want 5", overview.TotalProjects)
	}

	encoded, err := json.Marshal(overview)
	if err != nil {
		t.Fatalf("marshalling the overview failed: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("re-reading the encoded overview failed: %v", err)
	}
	if _, present := fields["riskScore"]; present {
		t.Error("riskScore is present in the output, want it omitted")
	}
}

// If the organization endpoint gains a cyberRisk block, it must be read.
func TestGetOrgOverview_ReadsCyberRisk(t *testing.T) {
	client := newOverviewTestClient(t, `{"cyberRisk": {"score": 120, "level": "high"}, "totalProjects": 2}`)

	overview, err := client.GetOrgOverview("o1", nil)
	if err != nil {
		t.Fatalf("GetOrgOverview returned an error: %v", err)
	}

	if overview.RiskScore == nil {
		t.Fatal("RiskScore is nil, want 120")
	}
	if *overview.RiskScore != 120 {
		t.Errorf("RiskScore = %v, want 120", *overview.RiskScore)
	}
	if overview.RiskLevel != "high" {
		t.Errorf("RiskLevel = %q, want %q", overview.RiskLevel, "high")
	}
}
