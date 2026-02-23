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
)

// GetSBOMReport downloads the SBOM report for a project.
// Returns the raw response body (JSON).
func (c *Client) GetSBOMReport(projectID string) ([]byte, error) {
	apiURL := fmt.Sprintf("%s/project/%s/sbom", c.APIURL, projectID)
	logger.Debug("GET %s", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// GetOWASPReport downloads the OWASP report for a project.
// format: json, html, pdf. detailed: whether to include detailed info.
func (c *Client) GetOWASPReport(projectID, format string, detailed bool) ([]byte, error) {
	q := url.Values{}
	if detailed {
		q.Set("detailed", "true")
	}

	apiURL := fmt.Sprintf("%s/project/%s/owasp-report/%s", c.APIURL, projectID, format)
	if encoded := q.Encode(); encoded != "" {
		apiURL += "?" + encoded
	}
	logger.Debug("GET %s", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// GetCWEReport downloads the CWE Top 25 report for a project.
func (c *Client) GetCWEReport(projectID, format string, detailed bool) ([]byte, error) {
	q := url.Values{}
	if detailed {
		q.Set("detailed", "true")
	}

	apiURL := fmt.Sprintf("%s/project/%s/cwe-report/%s", c.APIURL, projectID, format)
	if encoded := q.Encode(); encoded != "" {
		apiURL += "?" + encoded
	}
	logger.Debug("GET %s", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// GetOrgReport downloads an aggregated security report for an organization.
// reportType: owasp or cwe. format: json, html, pdf.
func (c *Client) GetOrgReport(organizationID, reportType, format string, detailed bool) ([]byte, error) {
	q := url.Values{}
	if detailed {
		q.Set("detailed", "true")
	}

	apiURL := fmt.Sprintf("%s/organization/%s/report/%s/%s", c.APIURL, organizationID, reportType, format)
	if encoded := q.Encode(); encoded != "" {
		apiURL += "?" + encoded
	}
	logger.Debug("GET %s", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// GetTeamReport downloads an aggregated security report for a team.
func (c *Client) GetTeamReport(teamID, reportType, format string, detailed bool) ([]byte, error) {
	q := url.Values{}
	if detailed {
		q.Set("detailed", "true")
	}

	apiURL := fmt.Sprintf("%s/team/%s/report/%s/%s", c.APIURL, teamID, reportType, format)
	if encoded := q.Encode(); encoded != "" {
		apiURL += "?" + encoded
	}
	logger.Debug("GET %s", apiURL)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// BatchReportRequest represents the request body for a batch (manual selection) report.
type BatchReportRequest struct {
	ProjectIDs []string `json:"projectIds"`
	Detailed   *bool    `json:"detailed,omitempty"`
}

// BatchReportResponse represents the envelope returned by the batch report API.
type BatchReportResponse struct {
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Content     string `json:"content"` // base64-encoded report data
}

// GetBatchReport generates a report for a manual selection of projects.
// Returns the decoded report bytes and the suggested filename.
func (c *Client) GetBatchReport(organizationID, reportType, format string, reqBody *BatchReportRequest) ([]byte, string, error) {
	apiURL := fmt.Sprintf("%s/organization/%s/project/report/batch/%s/%s", c.APIURL, organizationID, reportType, format)
	logger.Debug("POST %s", apiURL)

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("error creating request: %w", err)
	}
	token, err := c.GetAccessToken()
	if err != nil {
		return nil, "", fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("error reading response: %w", err)
	}
	logger.Debug("HTTP Status: %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, "", fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var envelope BatchReportResponse
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, "", fmt.Errorf("error parsing batch report response: %w", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(envelope.Content)
	if err != nil {
		return nil, "", fmt.Errorf("error decoding report content: %w", err)
	}

	return decoded, envelope.Filename, nil
}
