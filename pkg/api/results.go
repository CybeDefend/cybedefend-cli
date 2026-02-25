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

// Vulnerability represents a single vulnerability (flattened from API response).
type Vulnerability struct {
	ID                  string               `json:"id"`
	Language            string               `json:"language"`
	Path                string               `json:"path"`
	VulnerableStartLine int                  `json:"vulnerableStartLine"`
	VulnerableEndLine   int                  `json:"vulnerableEndLine"`
	Details             VulnerabilityDetails `json:"vulnerability"`
	Branch              string               `json:"branch"`
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

// apiScanResults is used internally to deserialize the raw API response.
type apiScanResults struct {
	ProjectID       string               `json:"projectId"`
	ProjectName     string               `json:"projectName"`
	Page            int                  `json:"page"`
	Total           int                  `json:"total"`
	TotalPages      int                  `json:"totalPages"`
	Severity        []string             `json:"severity"`
	Vulnerabilities []apiVulnerabilityWrapper `json:"vulnerabilities"`
}

// apiVulnerabilityWrapper reflects the actual API shape: each entry has a "base" object.
type apiVulnerabilityWrapper struct {
	Base apiVulnerabilityBase `json:"base"`
}

type apiVulnerabilityBase struct {
	ID                  string               `json:"id"`
	Language            string               `json:"language"`
	Path                string               `json:"path"`
	VulnerableStartLine int                  `json:"vulnerableStartLine"`
	VulnerableEndLine   int                  `json:"vulnerableEndLine"`
	Details             VulnerabilityDetails `json:"vulnerability"`
	Branch              string               `json:"branch"`
}

// GetResults fetches the results for the specified project, result type, page, and optional branch.
func (c *Client) GetResults(projectID, resultType string, page, limit int, branch string) (*ScanResults, error) {
	q := url.Values{}
	q.Set("pageNumber", strconv.Itoa(page))
	q.Set("sort", "currentSeverity")
	q.Set("order", "asc")
	q.Set("pageSizeNumber", strconv.Itoa(limit))
	for _, s := range []string{"critical", "high", "medium", "low"} {
		q.Add("severity[]", s)
	}
	for _, s := range []string{"to_verify", "confirmed"} {
		q.Add("status[]", s)
	}
	for _, s := range []string{"critical_urgent", "urgent", "normal", "low", "very_low"} {
		q.Add("priority[]", s)
	}
	if branch != "" {
		q.Set("branch", branch)
	}
	rawURL := fmt.Sprintf("%s/project/%s/results/%s?%s", c.APIURL, projectID, resultType, q.Encode())

	logger.Debug("GET %s", rawURL)

	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	token, err := c.GetAccessToken()
	if err != nil {
		return nil, fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %s", string(body))
	}

	var raw apiScanResults
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	// Flatten the nested "base" wrapper into the public Vulnerability type.
	vulns := make([]Vulnerability, 0, len(raw.Vulnerabilities))
	for _, w := range raw.Vulnerabilities {
		vulns = append(vulns, Vulnerability{
			ID:                  w.Base.ID,
			Language:            w.Base.Language,
			Path:                w.Base.Path,
			VulnerableStartLine: w.Base.VulnerableStartLine,
			VulnerableEndLine:   w.Base.VulnerableEndLine,
			Details:             w.Base.Details,
			Branch:              w.Base.Branch,
		})
	}

	return &ScanResults{
		ProjectID:       raw.ProjectID,
		ProjectName:     raw.ProjectName,
		Page:            raw.Page,
		Total:           raw.Total,
		TotalPages:      raw.TotalPages,
		Severity:        raw.Severity,
		Vulnerabilities: vulns,
	}, nil
}
