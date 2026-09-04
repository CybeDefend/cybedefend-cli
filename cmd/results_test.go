package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cybedefend-cli/pkg/api"
)

const scoredSastPage = `{
	"projectId": "p1", "projectName": "proj", "page": 1, "total": 1, "totalPages": 1,
	"vulnerabilities": [{
		"base": {
			"id": "v1", "currentSeverity": "high", "currentPriority": "urgent",
			"language": "go", "path": "main.go", "priorityScore": 61.5, "cvss4BaseScore": 8.1,
			"vulnerability": {"name": "SQL Injection", "severity": "HIGH", "cwe": ["CWE-89"]}
		},
		"metadata": {"cve": "CVE-2024-0001"}
	}]
}`

func newResultsPageClient(t *testing.T, page string) *api.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/oidc/token" {
			_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":600}`))
			return
		}
		_, _ = w.Write([]byte(page))
	}))
	t.Cleanup(srv.Close)
	return api.NewClient(srv.URL, "pat", srv.URL, "cid", srv.URL)
}

// Without --scores the output must keep its historical shape: no CVE, no
// severity/priority, no scores block, while the rest of the finding is intact.
func TestFetchResultsPage_StripsRiskDataUnlessScoresFlag(t *testing.T) {
	client := newResultsPageClient(t, scoredSastPage)
	projectIDResults, resultsBranch = "p1", ""

	includeScores = false
	t.Cleanup(func() { includeScores = false })
	res, err := fetchResultsPage(client, "sast", 1, 20)
	if err != nil {
		t.Fatalf("fetchResultsPage: %v", err)
	}
	v := res.Vulnerabilities[0]
	if v.CVE != "" || v.CurrentSeverity != "" || v.CurrentPriority != "" || v.Scores != nil {
		t.Errorf("risk data must be stripped without --scores, got %+v", v)
	}
	if v.ID != "v1" || v.Details.Name != "SQL Injection" || len(v.Details.CWE) != 1 {
		t.Errorf("non-risk fields must be preserved, got %+v", v)
	}

	includeScores = true
	res, err = fetchResultsPage(client, "sast", 1, 20)
	if err != nil {
		t.Fatalf("fetchResultsPage: %v", err)
	}
	v = res.Vulnerabilities[0]
	if v.CVE != "CVE-2024-0001" || v.CurrentPriority != "urgent" || v.Scores == nil || v.Scores.PriorityScore == nil {
		t.Errorf("risk data must be exposed with --scores, got %+v", v)
	}
}
