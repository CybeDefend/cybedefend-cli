// File: pkg/api/report.go

package api

import (
	"bytes"
	"cybedefend-cli/pkg/logger"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// The report endpoints do not return a report. They enqueue one and answer with
// a job: `{"reportId":"01M2...","status":"queued","downloadUrl":"","content":""}`.
// The report itself is fetched from `GET <scope>/reports/<reportId>` once that
// job reaches `ready`, which names a signed, expiring download URL.
//
// Writing the job envelope to the output file is what produced a 205-byte
// "report" — or, for the batch endpoint whose empty base64 `content` decoded to
// nothing, a 0-byte file announced as a success. Both are the failure the
// release notes for v2.0.4 already recorded once: a file downstream consumers
// cannot use, delivered as if it were fine.
const (
	reportStatusReady      = "ready"
	reportStatusFailed     = "failed"
	reportStatusQueued     = "queued"
	reportStatusProcessing = "processing"
)

const (
	reportPollInterval = 2 * time.Second
	// DefaultReportWait bounds how long the CLI waits for a queued report. The
	// job outlives the wait: a timeout says where to find it, it does not
	// cancel it.
	DefaultReportWait = 300 * time.Second
)

// reportJob is the shape both the generation endpoints and the status endpoint
// answer with. Not every field is populated at every stage — `downloadUrl` and
// `filename` arrive only with `ready`, and `content` belongs to the older
// synchronous envelope the batch endpoint used to return.
type reportJob struct {
	ReportID    string `json:"reportId"`
	Status      string `json:"status"`
	ReportKind  string `json:"reportKind"`
	Format      string `json:"format"`
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Content     string `json:"content"` // base64, legacy synchronous shape
	DownloadURL string `json:"downloadUrl"`
	Error       string `json:"error"`
}

// BatchReportRequest represents the request body for a batch (manual selection) report.
type BatchReportRequest struct {
	ProjectIDs []string `json:"projectIds"`
	Detailed   *bool    `json:"detailed,omitempty"`
}

// ── report retrieval ────────────────────────────────────────────────

// GetSBOMReport downloads the SBOM report for a project.
func (c *Client) GetSBOMReport(projectID string, wait time.Duration) ([]byte, string, error) {
	body, err := c.getReportBody(fmt.Sprintf("%s/project/%s/sbom", c.APIURL, projectID))
	if err != nil {
		return nil, "", err
	}
	return c.resolveReport("project/"+projectID, body, wait)
}

// GetOWASPReport downloads the OWASP Top 10 report for a project.
// format: json, html, pdf. detailed: whether to include detailed info.
func (c *Client) GetOWASPReport(projectID, format string, detailed bool, wait time.Duration) ([]byte, string, error) {
	apiURL := withDetailed(fmt.Sprintf("%s/project/%s/owasp-report/%s", c.APIURL, projectID, format), detailed)
	body, err := c.getReportBody(apiURL)
	if err != nil {
		return nil, "", err
	}
	return c.resolveReport("project/"+projectID, body, wait)
}

// GetCWEReport downloads the CWE Top 25 report for a project.
func (c *Client) GetCWEReport(projectID, format string, detailed bool, wait time.Duration) ([]byte, string, error) {
	apiURL := withDetailed(fmt.Sprintf("%s/project/%s/cwe-report/%s", c.APIURL, projectID, format), detailed)
	body, err := c.getReportBody(apiURL)
	if err != nil {
		return nil, "", err
	}
	return c.resolveReport("project/"+projectID, body, wait)
}

// GetOrgReport downloads an aggregated security report for an organization.
// reportType: owasp or cwe. format: json, html, pdf.
func (c *Client) GetOrgReport(organizationID, reportType, format string, detailed bool, wait time.Duration) ([]byte, string, error) {
	apiURL := withDetailed(fmt.Sprintf("%s/organization/%s/report/%s/%s", c.APIURL, organizationID, reportType, format), detailed)
	body, err := c.getReportBody(apiURL)
	if err != nil {
		return nil, "", err
	}
	return c.resolveReport("organization/"+organizationID, body, wait)
}

// GetTeamReport downloads an aggregated security report for a team.
func (c *Client) GetTeamReport(teamID, reportType, format string, detailed bool, wait time.Duration) ([]byte, string, error) {
	apiURL := withDetailed(fmt.Sprintf("%s/team/%s/report/%s/%s", c.APIURL, teamID, reportType, format), detailed)
	body, err := c.getReportBody(apiURL)
	if err != nil {
		return nil, "", err
	}
	return c.resolveReport("team/"+teamID, body, wait)
}

// GetBatchReport generates a report for a manual selection of projects.
func (c *Client) GetBatchReport(organizationID, reportType, format string, reqBody *BatchReportRequest, wait time.Duration) ([]byte, string, error) {
	apiURL := fmt.Sprintf("%s/organization/%s/project/report/batch/%s/%s", c.APIURL, organizationID, reportType, format)
	logger.Debug("POST %s", apiURL)

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(payload))
	if err != nil {
		return nil, "", fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	body, err := c.doReportRequest(req)
	if err != nil {
		return nil, "", err
	}
	return c.resolveReport("organization/"+organizationID, body, wait)
}

// ── shared plumbing ─────────────────────────────────────────────────

func withDetailed(apiURL string, detailed bool) string {
	if !detailed {
		return apiURL
	}
	q := url.Values{}
	q.Set("detailed", "true")
	return apiURL + "?" + q.Encode()
}

func (c *Client) getReportBody(apiURL string) ([]byte, error) {
	logger.Debug("GET %s", apiURL)
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	return c.doReportRequest(req)
}

func (c *Client) doReportRequest(req *http.Request) ([]byte, error) {
	token, err := c.GetAccessToken()
	if err != nil {
		return nil, fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}
	logger.Debug("HTTP Status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

// resolveReport turns whatever a report endpoint answered into the report
// itself, and returns the filename the API suggests for it.
//
// Three shapes have to be handled, because the API moved and not every
// deployment moved with it: a job to wait for (the current cloud), an envelope
// carrying the report inline as base64 (what the batch endpoint returned
// before), and the report itself (what the API reference still describes).
func (c *Client) resolveReport(scope string, respBody []byte, wait time.Duration) ([]byte, string, error) {
	var job reportJob
	if err := json.Unmarshal(respBody, &job); err != nil {
		// Not an envelope: HTML, a PDF, or a JSON document that is the report.
		return respBody, "", nil
	}

	switch {
	case job.Content != "":
		decoded, err := base64.StdEncoding.DecodeString(job.Content)
		if err != nil {
			return nil, "", fmt.Errorf("error decoding report content: %w", err)
		}
		return decoded, job.Filename, nil

	case job.ReportID != "":
		return c.waitForReport(scope, job.ReportID, wait)

	default:
		// A JSON report — an SBOM, for instance — which carries none of the
		// envelope's fields.
		return respBody, "", nil
	}
}

// waitForReport polls the job until the report exists, then downloads it.
func (c *Client) waitForReport(scope, reportID string, wait time.Duration) ([]byte, string, error) {
	statusURL := fmt.Sprintf("%s/%s/reports/%s", c.APIURL, scope, reportID)
	deadline := time.Now().Add(wait)

	for {
		body, err := c.getReportBody(statusURL)
		if err != nil {
			return nil, "", fmt.Errorf("cannot read the status of report %s: %w", reportID, err)
		}

		var job reportJob
		if err := json.Unmarshal(body, &job); err != nil {
			return nil, "", fmt.Errorf("unreadable status for report %s: %w", reportID, err)
		}

		switch job.Status {
		case reportStatusReady:
			if job.DownloadURL == "" {
				return nil, "", fmt.Errorf("report %s is ready but the API named no download URL", reportID)
			}
			data, err := downloadReport(job.DownloadURL)
			if err != nil {
				return nil, "", err
			}
			return data, job.Filename, nil

		case reportStatusFailed:
			reason := job.Error
			if reason == "" {
				reason = "the API gave no reason"
			}
			return nil, "", fmt.Errorf("generating report %s failed: %s", reportID, reason)

		case reportStatusQueued, reportStatusProcessing, "":
			// Still being generated.

		default:
			return nil, "", fmt.Errorf("report %s is in an unknown state %q", reportID, job.Status)
		}

		if time.Now().Before(deadline) {
			logger.Debug("report %s is %s, retrying in %s", reportID, job.Status, reportPollInterval)
			time.Sleep(reportPollInterval)
			continue
		}

		// The job outlives this wait: saying so is more useful than implying
		// the report was lost.
		return nil, "", fmt.Errorf(
			"report %s is still %q after %s. It keeps generating server-side — "+
				"retry with a longer --timeout, or fetch it from %s",
			reportID, job.Status, wait, statusURL)
	}
}

// downloadClient fetches the signed report URL. It is a variable so a test can
// point it at a local TLS server holding its own certificate, without the https
// requirement below having to be relaxed for the test's sake.
var downloadClient = http.DefaultClient

// downloadReport fetches the finished report from the signed URL the API named.
//
// No Authorization header is sent: the URL points at object storage on another
// host and already carries its own signature, so attaching the API bearer token
// would hand it to a third party for nothing.
func downloadReport(downloadURL string) ([]byte, error) {
	parsed, err := url.Parse(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("the API named an unusable download URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("refusing to download the report over %q: only https is accepted", parsed.Scheme)
	}
	logger.Debug("GET %s (signed download)", parsed.Host+parsed.Path)

	resp, err := downloadClient.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("downloading the report failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the downloaded report failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading the report failed (HTTP %d): %s", resp.StatusCode, truncate(data, 200))
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("the download URL returned an empty report")
	}
	return data, nil
}

func truncate(data []byte, max int) string {
	if len(data) <= max {
		return string(data)
	}
	return string(data[:max]) + "..."
}
