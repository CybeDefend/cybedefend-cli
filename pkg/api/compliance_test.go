package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newComplianceTestClient returns a Client pointed at a test server that
// answers the token exchange and serves the given JSON for every other route.
func newComplianceTestClient(t *testing.T, body string) *Client {
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

// The API wraps violation stats in a "stats" object. Reading the flat shape
// reported zero violations for a project that a policy had actually blocked.
func TestGetViolationStats_ReadsStatsEnvelope(t *testing.T) {
	client := newComplianceTestClient(t, `{
		"stats": {
			"totalViolations": 1,
			"blockedCount": 1,
			"warnedCount": 0,
			"applicablePoliciesCount": 1,
			"complianceStatus": "Non-Compliant"
		}
	}`)

	stats, err := client.GetViolationStats("p1", "", "")
	if err != nil {
		t.Fatalf("GetViolationStats returned an error: %v", err)
	}

	if stats.TotalViolations != 1 {
		t.Errorf("TotalViolations = %d, want 1", stats.TotalViolations)
	}
	if stats.BlockedCount != 1 {
		t.Errorf("BlockedCount = %d, want 1", stats.BlockedCount)
	}
	if stats.ApplicablePoliciesCount != 1 {
		t.Errorf("ApplicablePoliciesCount = %d, want 1", stats.ApplicablePoliciesCount)
	}
	if stats.ComplianceStatus != "Non-Compliant" {
		t.Errorf("ComplianceStatus = %q, want %q", stats.ComplianceStatus, "Non-Compliant")
	}
}

// An API that drops the envelope must keep working.
func TestGetViolationStats_AcceptsFlatShape(t *testing.T) {
	client := newComplianceTestClient(t, `{
		"totalViolations": 3,
		"blockedCount": 2,
		"warnedCount": 1,
		"applicablePoliciesCount": 4,
		"complianceStatus": "Non-Compliant"
	}`)

	stats, err := client.GetViolationStats("p1", "", "")
	if err != nil {
		t.Fatalf("GetViolationStats returned an error: %v", err)
	}

	if stats.TotalViolations != 3 {
		t.Errorf("TotalViolations = %d, want 3", stats.TotalViolations)
	}
	if stats.WarnedCount != 1 {
		t.Errorf("WarnedCount = %d, want 1", stats.WarnedCount)
	}
	if stats.ComplianceStatus != "Non-Compliant" {
		t.Errorf("ComplianceStatus = %q, want %q", stats.ComplianceStatus, "Non-Compliant")
	}
}

// A compliant project legitimately reports zeros; that must survive the
// envelope handling rather than being mistaken for a decode failure.
func TestGetViolationStats_CompliantProjectKeepsZeros(t *testing.T) {
	client := newComplianceTestClient(t, `{
		"stats": {
			"totalViolations": 0,
			"blockedCount": 0,
			"warnedCount": 0,
			"applicablePoliciesCount": 2,
			"complianceStatus": "Compliant"
		}
	}`)

	stats, err := client.GetViolationStats("p1", "", "")
	if err != nil {
		t.Fatalf("GetViolationStats returned an error: %v", err)
	}

	if stats.TotalViolations != 0 {
		t.Errorf("TotalViolations = %d, want 0", stats.TotalViolations)
	}
	if stats.ApplicablePoliciesCount != 2 {
		t.Errorf("ApplicablePoliciesCount = %d, want 2", stats.ApplicablePoliciesCount)
	}
	if stats.ComplianceStatus != "Compliant" {
		t.Errorf("ComplianceStatus = %q, want %q", stats.ComplianceStatus, "Compliant")
	}
}
