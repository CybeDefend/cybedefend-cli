package api

import (
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// EvaluationStatus represents the policy evaluation status response
type EvaluationStatus struct {
	HasEvaluation bool   `json:"hasEvaluation"`
	EvaluationId  string `json:"evaluationId,omitempty"`
	Status        string `json:"status"` // PENDING, IN_PROGRESS, COMPLETED, FAILED, NOT_STARTED
	Progress      int    `json:"progress"`
	Message       string `json:"message"`
	StartedAt     string `json:"startedAt,omitempty"`
	CompletedAt   string `json:"completedAt,omitempty"`
}

// PolicyRule represents a rule within a policy violation
type PolicyRule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Type        string      `json:"type"`
	Value       interface{} `json:"value"`
	Action      string      `json:"action"`
	Operator    string      `json:"operator"`
}

// AffectedVulnerability represents a vulnerability affected by a policy violation
type AffectedVulnerability struct {
	ID                string   `json:"id"`
	CWE               []string `json:"cwe,omitempty"`
	Name              string   `json:"name"`
	Branch            string   `json:"branch,omitempty"`
	EndLine           int      `json:"endLine,omitempty"`
	FilePath          string   `json:"filePath,omitempty"`
	Severity          string   `json:"severity"`
	CVSSScore         float64  `json:"cvssScore,omitempty"`
	StartLine         int      `json:"startLine,omitempty"`
	OwaspTop10        []string `json:"owaspTop10,omitempty"`
	VulnerabilityType string   `json:"vulnerabilityType"` // sast or sca
	PackageName       string   `json:"packageName,omitempty"`
	PackageVersion    string   `json:"packageVersion,omitempty"`
}

// PolicyViolation represents a single policy violation
type PolicyViolation struct {
	ID                           string                  `json:"id"`
	PolicyId                     string                  `json:"policyId"`
	ProjectId                    string                  `json:"projectId"`
	ScanId                       string                  `json:"scanId"`
	OrganizationId               string                  `json:"organizationId"`
	ActionTaken                  string                  `json:"actionTaken"` // BLOCK or WARN
	AffectedVulnerabilitiesCount int                     `json:"affectedVulnerabilitiesCount"`
	AffectedVulnerabilities      []AffectedVulnerability `json:"affectedVulnerabilities,omitempty"`
	Rule                         PolicyRule              `json:"rule"`
	Acknowledged                 bool                    `json:"acknowledged"`
	AcknowledgedAt               string                  `json:"acknowledgedAt,omitempty"`
	AcknowledgementReason        string                  `json:"acknowledgementReason,omitempty"`
	CreatedAt                    string                  `json:"createdAt"`
	UpdatedAt                    string                  `json:"updatedAt"`
}

// ViolationsResponse represents paginated violations
type ViolationsResponse struct {
	Violations []PolicyViolation `json:"violations"`
	Total      int               `json:"total"`
	Page       int               `json:"page"`
	Limit      int               `json:"limit"`
}

// GetEvaluationStatus retrieves the policy evaluation status for a scan
func (c *Client) GetEvaluationStatus(projectId, scanId string) (*EvaluationStatus, error) {
	url := fmt.Sprintf("%s/projects/%s/scans/%s/evaluation-status",
		c.APIURL, projectId, scanId)

	logger.Debug("GET %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("x-api-key", c.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	logger.Debug("HTTP Status: %d", resp.StatusCode)
	logger.Debug("Response Body: %s", string(responseBody))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d - response: %s", resp.StatusCode, string(responseBody))
	}

	var evalStatus EvaluationStatus
	if err := json.Unmarshal(responseBody, &evalStatus); err != nil {
		return nil, fmt.Errorf("error parsing evaluation status response: %w", err)
	}

	return &evalStatus, nil
}

// GetViolations retrieves a paginated list of policy violations for a scan
func (c *Client) GetViolations(projectId, scanId string, page, limit int) (*ViolationsResponse, error) {
	url := fmt.Sprintf("%s/projects/%s/scans/%s/violations?page=%d&limit=%d",
		c.APIURL, projectId, scanId, page, limit)

	logger.Debug("GET %s", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("x-api-key", c.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	logger.Debug("HTTP Status: %d", resp.StatusCode)
	logger.Debug("Response Body: %s", string(responseBody))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d - response: %s", resp.StatusCode, string(responseBody))
	}

	var violationsResp ViolationsResponse
	if err := json.Unmarshal(responseBody, &violationsResp); err != nil {
		return nil, fmt.Errorf("error parsing violations response: %w", err)
	}

	return &violationsResp, nil
}

// GetAllViolations fetches all violations by handling pagination automatically
func (c *Client) GetAllViolations(projectId, scanId string) ([]PolicyViolation, error) {
	var allViolations []PolicyViolation
	page := 1
	limit := 50

	for {
		resp, err := c.GetViolations(projectId, scanId, page, limit)
		if err != nil {
			return nil, err
		}

		allViolations = append(allViolations, resp.Violations...)

		// Check if we've fetched all violations
		if len(allViolations) >= resp.Total || len(resp.Violations) == 0 {
			break
		}

		page++
	}

	return allViolations, nil
}
