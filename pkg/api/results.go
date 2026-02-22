package api

import (
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ScanResults represents the scan results structure.
type ScanResults struct {
	ProjectID       string          `json:"projectId"`
	ProjectName     string          `json:"projectName"`
	Page            int             `json:"page"`
	Total           int             `json:"total"`
	TotalPages      int             `json:"totalPages"`
	Severity        []string        `json:"severity"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability represents a single vulnerability.
type Vulnerability struct {
	ID                  string               `json:"id"`
	Language            string               `json:"language"`
	Path                string               `json:"path"`
	VulnerableStartLine int                  `json:"vulnerableStartLine"`
	VulnerableEndLine   int                  `json:"vulnerableEndLine"`
	Details             VulnerabilityDetails `json:"vulnerability"`
}

type VulnerabilityDetails struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Severity          string   `json:"severity"`
	HowToPrevent      string   `json:"howToPrevent"`
	CWE               []string `json:"cwe"`
	OWASP             []string `json:"owaspTop10"`
	VulnerabilityType string   `json:"vulnerabilityType"`
}

// GetResults fetches the results for the specified project, result type, and page.
func (c *Client) GetResults(projectID, resultType string, page, limit int) (*ScanResults, error) {
	baseURL := fmt.Sprintf("%s/project/%s/results/%s", c.APIURL, projectID, resultType)

	params := url.Values{}
	params.Set("pageNumber", fmt.Sprintf("%d", page))
	params.Set("sort", "currentSeverity")
	params.Set("order", "asc")
	params.Set("pageSizeNumber", fmt.Sprintf("%d", limit))

	for _, s := range []string{"critical", "high", "medium", "low"} {
		params.Add("severity", s)
	}
	for _, s := range []string{"to_verify", "confirmed"} {
		params.Add("status", s)
	}
	for _, s := range []string{"critical_urgent", "urgent", "normal", "low", "very_low"} {
		params.Add("priority", s)
	}

	fullURL := baseURL + "?" + params.Encode()

	logger.Debug("GET %s", fullURL)

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", c.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s", string(body))
	}

	var results ScanResults
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	return &results, nil
}
