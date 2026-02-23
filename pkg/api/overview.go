package api

import (
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ProjectOverview represents the project-level overview response.
type ProjectOverview struct {
	TotalBySeverity         []SeverityCount             `json:"totalBySeverity"`
	TotalByState            []StateCount                `json:"totalByState"`
	TotalByAnalysisType     []AnalysisTypeCount         `json:"totalByAnalysisType"`
	VulnerabilitiesOverTime []VulnerabilityOverTimeEntry `json:"vulnerabilitiesOverTime"`
	RiskScore               float64                     `json:"riskScore"`
	RiskLevel               string                      `json:"riskLevel"`
}

// SeverityCount is a severity + count pair.
type SeverityCount struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// StateCount is a state + count pair.
type StateCount struct {
	State string `json:"state"`
	Count int    `json:"count"`
}

// AnalysisTypeCount is an analysis type + count pair.
type AnalysisTypeCount struct {
	AnalysisType string `json:"analysisType"`
	Count        int    `json:"count"`
}

// VulnerabilityOverTimeEntry is a single data point for vulnerabilities over time.
type VulnerabilityOverTimeEntry struct {
	Date     string `json:"date"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// OrgOverview represents the organization-level overview response.
type OrgOverview struct {
	TotalBySeverity         json.RawMessage             `json:"totalBySeverity"`
	TotalByState            json.RawMessage             `json:"totalByState"`
	TotalByAnalysisType     json.RawMessage             `json:"totalByAnalysisType"`
	VulnerabilitiesOverTime json.RawMessage             `json:"vulnerabilitiesOverTime"`
	RiskScore               float64                     `json:"riskScore"`
	RiskLevel               string                      `json:"riskLevel"`
	TotalProjects           int                         `json:"totalProjects,omitempty"`
	TotalScans              int                         `json:"totalScans,omitempty"`
	ProjectSummaries        json.RawMessage             `json:"projectSummaries,omitempty"`
	TrendData               json.RawMessage             `json:"trendData,omitempty"`
}

// GetProjectOverview retrieves the results overview for a project.
func (c *Client) GetProjectOverview(projectID string, branches []string) (*ProjectOverview, error) {
	q := url.Values{}
	for _, b := range branches {
		q.Add("branches", b)
	}

	apiURL := fmt.Sprintf("%s/project/%s/results/overview", c.APIURL, projectID)
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

	respBody, _ := io.ReadAll(resp.Body)
	logger.Debug("HTTP Status: %d", resp.StatusCode)
	logger.Debug("Response Body: %s", string(respBody))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var overview ProjectOverview
	if err := json.Unmarshal(respBody, &overview); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &overview, nil
}

// OrgOverviewParams holds query parameters for the organization overview endpoint.
type OrgOverviewParams struct {
	SeverityFilter  []string
	StatusFilter    []string
	AnalysisTypes   []string
	DateFrom        string
	DateTo          string
	Branches        []string
	TeamIDs         []string
	TrendPeriodDays int
}

// GetOrgOverview retrieves the results overview for an organization.
func (c *Client) GetOrgOverview(organizationID string, params *OrgOverviewParams) (*OrgOverview, error) {
	q := url.Values{}
	if params != nil {
		for _, v := range params.SeverityFilter {
			q.Add("severityFilter", v)
		}
		for _, v := range params.StatusFilter {
			q.Add("statusFilter", v)
		}
		for _, v := range params.AnalysisTypes {
			q.Add("analysisTypes", v)
		}
		if params.DateFrom != "" {
			q.Set("dateFrom", params.DateFrom)
		}
		if params.DateTo != "" {
			q.Set("dateTo", params.DateTo)
		}
		for _, v := range params.Branches {
			q.Add("branches", v)
		}
		for _, v := range params.TeamIDs {
			q.Add("teamIds", v)
		}
		if params.TrendPeriodDays > 0 {
			q.Set("trendPeriodDays", fmt.Sprintf("%d", params.TrendPeriodDays))
		}
	}

	apiURL := fmt.Sprintf("%s/organization/%s/results/overview", c.APIURL, organizationID)
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

	respBody, _ := io.ReadAll(resp.Body)
	logger.Debug("HTTP Status: %d", resp.StatusCode)
	logger.Debug("Response Body: %s", string(respBody))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var overview OrgOverview
	if err := json.Unmarshal(respBody, &overview); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &overview, nil
}
