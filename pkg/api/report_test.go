// File: pkg/api/report_test.go

package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// reportServer stands in for a CybeDefend instance: it mints a token, answers
// the generation endpoint with whatever `generated` says, and serves the report
// status from `statuses`, one entry per poll.
type reportServer struct {
	generated string
	statuses  []string
	polls     int
}

func (s *reportServer) start(t *testing.T) *Client {
	t.Helper()

	// The signed download URL points at object storage, on its own host and
	// over https — served here by a TLS server with its own certificate.
	storage := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			// The API bearer token has no business reaching object storage.
			http.Error(w, "the API token was leaked to storage", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, "THE REPORT BYTES")
	}))
	t.Cleanup(storage.Close)

	previous := downloadClient
	downloadClient = storage.Client()
	t.Cleanup(func() { downloadClient = previous })

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oidc/token":
			fmt.Fprint(w, `{"access_token":"tok","expires_in":600}`)

		case strings.Contains(r.URL.Path, "/reports/"):
			i := s.polls
			if i >= len(s.statuses) {
				i = len(s.statuses) - 1
			}
			s.polls++
			fmt.Fprint(w, strings.ReplaceAll(s.statuses[i], "STORAGE", storage.URL+"/report"))

		default:
			fmt.Fprint(w, s.generated)
		}
	}))
	t.Cleanup(api.Close)

	return NewClient(api.URL, "pat", api.URL, "cid", api.URL)
}

// The current cloud answers the generation endpoint with a job, not a report.
// Writing that job to the output file is what produced a 205-byte "report".
func TestGetOWASPReport_WaitsForTheJobThenDownloadsIt(t *testing.T) {
	srv := &reportServer{
		generated: `{"reportId":"01M2","status":"queued","content":"","downloadUrl":""}`,
		statuses: []string{
			`{"reportId":"01M2","status":"queued"}`,
			`{"reportId":"01M2","status":"processing"}`,
			`{"reportId":"01M2","status":"ready","filename":"owasp-p1.json","downloadUrl":"STORAGE"}`,
		},
	}
	client := srv.start(t)

	data, filename, err := client.GetOWASPReport("p1", "json", false, 30*time.Second)
	if err != nil {
		t.Fatalf("GetOWASPReport returned %v", err)
	}
	if string(data) != "THE REPORT BYTES" {
		t.Errorf("got %q, want the downloaded report", data)
	}
	if filename != "owasp-p1.json" {
		t.Errorf("filename = %q, want the name the API suggested", filename)
	}
	if srv.polls < 3 {
		t.Errorf("polled %d times, expected it to wait through queued and processing", srv.polls)
	}
}

// A failed job must not produce a file. It used to be indistinguishable from a
// report, because the envelope was written either way.
func TestGetOWASPReport_FailedJobIsAnError(t *testing.T) {
	srv := &reportServer{
		generated: `{"reportId":"01M2","status":"queued"}`,
		statuses:  []string{`{"reportId":"01M2","status":"failed","error":"the project has no scan"}`},
	}
	client := srv.start(t)

	data, _, err := client.GetOWASPReport("p1", "json", false, 30*time.Second)
	if err == nil {
		t.Fatalf("expected an error, got %d bytes", len(data))
	}
	for _, want := range []string{"01M2", "the project has no scan"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if data != nil {
		t.Errorf("a failed report must yield no bytes, got %q", data)
	}
}

// A report that is still generating when the wait runs out is not lost, and the
// error has to say so rather than imply the command should be repeated blindly.
func TestGetOWASPReport_TimeoutNamesTheJob(t *testing.T) {
	srv := &reportServer{
		generated: `{"reportId":"01M2","status":"queued"}`,
		statuses:  []string{`{"reportId":"01M2","status":"processing"}`},
	}
	client := srv.start(t)

	_, _, err := client.GetOWASPReport("p1", "json", false, time.Millisecond)
	if err == nil {
		t.Fatal("expected the wait to run out")
	}
	for _, want := range []string{"01M2", "processing", "generating server-side"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// The batch endpoint used to return the report inline as base64. A deployment
// that still does must keep working.
func TestGetBatchReport_DecodesTheInlineEnvelope(t *testing.T) {
	content := base64.StdEncoding.EncodeToString([]byte("INLINE REPORT"))
	srv := &reportServer{
		generated: fmt.Sprintf(`{"filename":"batch.json","contentType":"application/json","content":%q}`, content),
	}
	client := srv.start(t)

	data, filename, err := client.GetBatchReport("o1", "owasp", "json", &BatchReportRequest{ProjectIDs: []string{"p1"}}, 30*time.Second)
	if err != nil {
		t.Fatalf("GetBatchReport returned %v", err)
	}
	if string(data) != "INLINE REPORT" || filename != "batch.json" {
		t.Errorf("got %q / %q", data, filename)
	}
	if srv.polls != 0 {
		t.Errorf("an inline report must not be polled for, polled %d times", srv.polls)
	}
}

// The API reference still describes these endpoints as returning the report
// itself, and the SBOM endpoint still does. Neither is an envelope, and both
// have to pass through untouched.
func TestResolveReport_PassesThroughARealReport(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"a JSON report carrying none of the envelope fields", `{"id":"s1","projectId":"p1","sbomJson":{"components":[]}}`},
		{"an HTML report", "<!DOCTYPE html><html><body>report</body></html>"},
		{"a JSON array", `[{"finding":1}]`},
	} {
		srv := &reportServer{generated: tc.body}
		client := srv.start(t)

		data, _, err := client.GetSBOMReport("p1", 30*time.Second)
		if err != nil {
			t.Errorf("%s: returned %v", tc.name, err)
			continue
		}
		if string(data) != tc.body {
			t.Errorf("%s: got %q, want it untouched", tc.name, data)
		}
	}
}

// A ready job with nothing behind it is the 0-byte file the release notes for
// v2.0.4 already recorded once. It has to be an error, not a success.
func TestWaitForReport_RefusesAnEmptyDownload(t *testing.T) {
	empty := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(empty.Close)
	previous := downloadClient
	downloadClient = empty.Client()
	t.Cleanup(func() { downloadClient = previous })

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oidc/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":600}`)
			return
		}
		if strings.Contains(r.URL.Path, "/reports/") {
			fmt.Fprintf(w, `{"reportId":"01M2","status":"ready","downloadUrl":%q}`, empty.URL+"/x")
			return
		}
		fmt.Fprint(w, `{"reportId":"01M2","status":"queued"}`)
	}))
	t.Cleanup(api.Close)

	client := NewClient(api.URL, "pat", api.URL, "cid", api.URL)
	if _, _, err := client.GetOWASPReport("p1", "json", false, 30*time.Second); err == nil {
		t.Fatal("an empty download must be an error, not a 0-byte report")
	}
}

// The download URL comes from the API response. Following a plain-http one would
// send the report — and the request — over the network in the clear.
func TestDownloadReport_RequiresHTTPS(t *testing.T) {
	if _, err := downloadReport("http://storage.example/report"); err == nil {
		t.Fatal("expected plain http to be refused")
	}
}
