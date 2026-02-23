package api

import (
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// ComplianceEntry represents a single compliance history entry.
type ComplianceEntry struct {
	ScanID                  string `json:"scanId"`
	Compliant               bool   `json:"compliant"`
	BlockingViolationsCount int    `json:"blockingViolationsCount"`
	WarningViolationsCount  int    `json:"warningViolationsCount"`
	EvaluatedAt             string `json:"evaluatedAt"`
	BreakingRulesCount      int    `json:"breakingRulesCount"`
	EvaluationID            string `json:"evaluationId"`
}

// ComplianceHistoryResponse represents the paginated compliance history response.
type ComplianceHistoryResponse struct {
	Entries  []ComplianceEntry `json:"entries"`
	Total    int               `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"pageSize"`
}

// ViolationStatsResponse represents the violation statistics for a project.
type ViolationStatsResponse struct {
	TotalViolations         int    `json:"totalViolations"`
	BlockedCount            int    `json:"blockedCount"`
	WarnedCount             int    `json:"warnedCount"`
	ApplicablePoliciesCount int    `json:"applicablePoliciesCount"`
	ComplianceStatus        string `json:"complianceStatus"` // Compliant, Non-Compliant, Pending
}

// GetComplianceHistory retrieves the compliance history for a project.
func (c *Client) GetComplianceHistory(projectID string, page, pageSize int, startDate, endDate string) (*ComplianceHistoryResponse, error) {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Set("pageSize", strconv.Itoa(pageSize))
	}
	if startDate != "" {
		q.Set("startDate", startDate)
	}
	if endDate != "" {
		q.Set("endDate", endDate)
	}

	apiURL := fmt.Sprintf("%s/projects/%s/compliance-history", c.APIURL, projectID)
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

	var result ComplianceHistoryResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &result, nil
}

// GetProjectViolations retrieves policy violations for a project (different from scan-level violations in policy.go).
func (c *Client) GetProjectViolations(projectID string, page, limit int) (*ViolationsResponse, error) {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}

	apiURL := fmt.Sprintf("%s/projects/%s/violations", c.APIURL, projectID)
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

	var result ViolationsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &result, nil
}

// GetViolationStats retrieves violation statistics for a project.
func (c *Client) GetViolationStats(projectID string, startDate, endDate string) (*ViolationStatsResponse, error) {
	q := url.Values{}
	if startDate != "" {
		q.Set("startDate", startDate)
	}
	if endDate != "" {
		q.Set("endDate", endDate)
	}

	apiURL := fmt.Sprintf("%s/projects/%s/violation-stats", c.APIURL, projectID)
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

	var result ViolationStatsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &result, nil
}
