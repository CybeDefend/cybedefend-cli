package api

import (
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ValidScanTypes lists all accepted scan type values.
var ValidScanTypes = []string{"sast", "sca", "iac", "secret", "cicd", "container", "all"}

// ─────────────────────────────────────────────────────────────────────────────
// Flat results (all individual scan types)
// ─────────────────────────────────────────────────────────────────────────────

// ScanResults is the public representation of a flat results page.
type ScanResults struct {
	ProjectID       string          `json:"projectId"`
	ProjectName     string          `json:"projectName"`
	Page            int             `json:"page"`
	Total           int             `json:"total"`
	TotalPages      int             `json:"totalPages"`
	Severity        []string        `json:"severity"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability is a single vulnerability, flattened from the API "base" wrapper.
type Vulnerability struct {
	ID                  string               `json:"id"`
	Language            string               `json:"language"`
	Path                string               `json:"path"`
	VulnerableStartLine int                  `json:"vulnerableStartLine"`
	VulnerableEndLine   int                  `json:"vulnerableEndLine"`
	Details             VulnerabilityDetails `json:"vulnerability"`
	Branch              string               `json:"branch"`
}

// VulnerabilityDetails holds the detail block nested inside a Vulnerability.
type VulnerabilityDetails struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Severity          string   `json:"severity"`
	HowToPrevent      string   `json:"howToPrevent"`
	CWE               []string `json:"cwe"`
	OWASP             []string `json:"owaspTop10"`
	VulnerabilityType string   `json:"vulnerabilityType"`
}

// AllScanResults is returned when --type all is requested (flat, typed by scan category).
type AllScanResults struct {
	ProjectID   string          `json:"projectId"`
	ProjectName string          `json:"projectName"`
	SAST        []Vulnerability `json:"sast"`
	SCA         []Vulnerability `json:"sca"`
	IAC         []Vulnerability `json:"iac"`
	Secret      []Vulnerability `json:"secret"`
	CICD        []Vulnerability `json:"cicd"`
	Container   []Vulnerability `json:"container"`
}

// ─── internal deserialization helpers ───────────────────────────────────────

type apiScanResults struct {
	ProjectID       string                    `json:"projectId"`
	ProjectName     string                    `json:"projectName"`
	Page            int                       `json:"page"`
	Total           int                       `json:"total"`
	TotalPages      int                       `json:"totalPages"`
	Severity        []string                  `json:"severity"`
	Vulnerabilities []apiVulnerabilityWrapper `json:"vulnerabilities"`
}

type apiVulnerabilityWrapper struct {
	Base           apiVulnerabilityBase `json:"base"`
	AutofixRecords []scaAutofixRecord   `json:"autofixRecords"`
	Library        *scaLibrary          `json:"library,omitempty"`
	Metadata       *scaMetadata         `json:"metadata,omitempty"`
}

type apiVulnerabilityBase struct {
	ID                  string               `json:"id"`
	CurrentSeverity     string               `json:"currentSeverity"`
	Language            string               `json:"language"`
	Path                string               `json:"path"`
	VulnerableStartLine int                  `json:"vulnerableStartLine"`
	VulnerableEndLine   int                  `json:"vulnerableEndLine"`
	Details             VulnerabilityDetails `json:"vulnerability"`
	Branch              string               `json:"branch"`
}

// scaAutofixRecord is the per-package autofix suggestion returned by the SCA endpoint.
type scaAutofixRecord struct {
	CveID                      string `json:"cveId"`
	VulnerablePackage          string `json:"vulnerablePackage"`
	VulnerableVersion          string `json:"vulnerableVersion"`
	RecommendedProposedVersion string `json:"recommendedProposedVersion"`
	InstallCommand             string `json:"installCommand"`
	HasFixAvailable            bool   `json:"hasFixAvailable"`
}

// scaLibrary holds the dependency (library) information for SCA findings.
type scaLibrary struct {
	PackageName    string   `json:"packageName"`
	PackageVersion string   `json:"packageVersion"`
	FileName       string   `json:"fileName"`
	Ecosystem      string   `json:"ecosystem"`
	Path           []string `json:"path"`
}

// scaMetadataCWE is a single CWE entry inside SCA metadata.
type scaMetadataCWE struct {
	CweID string `json:"cweId"`
}

// scaMetadataAlias is a single alias (CVE, etc.) inside SCA metadata.
type scaMetadataAlias struct {
	Alias string `json:"alias"`
}

// scaMetadata is the vulnerability advisory metadata for SCA findings.
type scaMetadata struct {
	GHSAID  string             `json:"ghsaId"`
	CVE     string             `json:"cve"`
	Summary string             `json:"summary"`
	Details string             `json:"details"`
	CWEs    []scaMetadataCWE   `json:"cwes"`
	Aliases []scaMetadataAlias `json:"aliases"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Grouped results (sast/iac/sca/secret/cicd)
// ─────────────────────────────────────────────────────────────────────────────

// GroupedScanResults is the response from /results/{type}/grouped endpoints.
type GroupedScanResults struct {
	ProjectID              string                 `json:"projectId"`
	ProjectName            string                 `json:"projectName"`
	Page                   int                    `json:"page"`
	Limit                  int                    `json:"limit"`
	TotalPages             int                    `json:"totalPages"`
	Total                  int                    `json:"total"`
	TotalOccurrences       int                    `json:"totalOccurrences"`
	Sort                   string                 `json:"sort"`
	Order                  string                 `json:"order"`
	Severity               []string               `json:"severity"`
	Status                 []string               `json:"status"`
	Priority               []string               `json:"priority"`
	GroupedVulnerabilities []GroupedVulnerability `json:"groupedVulnerabilities"`
}

// GroupedVulnerability is one rule/CVE group returned by a grouped endpoint.
type GroupedVulnerability struct {
	RuleID            string              `json:"ruleId,omitempty"`
	CveID             string              `json:"cveId,omitempty"`
	PackageName       string              `json:"packageName,omitempty"`
	OccurrenceCount   int                 `json:"occurrenceCount"`
	SeverityBreakdown SeverityBreakdown   `json:"severityBreakdown"`
	HighestSeverity   string              `json:"highestSeverity"`
	HighestCvss       float64             `json:"highestCvss,omitempty"`
	Language          string              `json:"language,omitempty"`
	Occurrences       []GroupedOccurrence `json:"occurrences"`
	HasAutofix        bool                `json:"hasAutofix"`
	FirstSeen         string              `json:"firstSeen"`
	LastSeen          string              `json:"lastSeen"`
	Vulnerability     json.RawMessage     `json:"vulnerability,omitempty"`
}

// SeverityBreakdown holds per-level counts inside a grouped vulnerability.
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// GroupedOccurrence is a single occurrence within a grouped vulnerability.
type GroupedOccurrence struct {
	ID                  string   `json:"id"`
	Path                string   `json:"path"`
	PackageVersion      string   `json:"packageVersion,omitempty"`
	VulnerableStartLine int      `json:"vulnerableStartLine,omitempty"`
	VulnerableEndLine   int      `json:"vulnerableEndLine,omitempty"`
	CurrentState        string   `json:"currentState"`
	CurrentSeverity     string   `json:"currentSeverity"`
	CurrentPriority     string   `json:"currentPriority"`
	CurrentCvss         float64  `json:"currentCvss,omitempty"`
	CreatedAt           string   `json:"createdAt"`
	IsDev               bool     `json:"isDev,omitempty"`
	IsTransitive        bool     `json:"isTransitive,omitempty"`
	AutofixRecords      []string `json:"autofixRecords,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Container grouped results
// ─────────────────────────────────────────────────────────────────────────────

// ContainerGroupedResults is the response from /results/container/images/grouped.
type ContainerGroupedResults struct {
	ProjectName       string           `json:"projectName"`
	GroupedImages     []ContainerImage `json:"groupedImages"`
	TotalRepositories int              `json:"totalRepositories"`
	TotalTags         int              `json:"totalTags"`
	TotalPages        int              `json:"totalPages"`
	CurrentPage       int              `json:"currentPage"`
	PageSize          int              `json:"pageSize"`
}

// ContainerImage is a single repository entry within grouped container results.
type ContainerImage struct {
	RepositoryName       string         `json:"repositoryName"`
	ProjectID            string         `json:"projectId"`
	OsFamily             string         `json:"osFamily"`
	OsName               string         `json:"osName"`
	Branch               string         `json:"branch"`
	TagCount             int            `json:"tagCount"`
	Tags                 []ContainerTag `json:"tags"`
	AggregatedVulnCounts VulnCounts     `json:"aggregatedVulnCounts"`
	LatestScanAt         string         `json:"latestScanAt"`
}

// ContainerTag is a single image tag within a container repository.
type ContainerTag struct {
	ID         string     `json:"id"`
	Tag        string     `json:"tag"`
	ScanID     string     `json:"scanId"`
	CreatedAt  string     `json:"createdAt"`
	UpdatedAt  string     `json:"updatedAt"`
	VulnCounts VulnCounts `json:"vulnCounts"`
}

// VulnCounts holds severity-bucketed vulnerability counts.
type VulnCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// ─────────────────────────────────────────────────────────────────────────────
// API methods
// ─────────────────────────────────────────────────────────────────────────────

// GetResults fetches one page of flat results for the given scan type and optional branch.
func (c *Client) GetResults(projectID, scanType string, page, limit int, branch string) (*ScanResults, error) {
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
	rawURL := fmt.Sprintf("%s/project/%s/results/%s?%s", c.APIURL, projectID, scanType, q.Encode())
	logger.Debug("GET %s", rawURL)

	raw, err := c.doGet(rawURL)
	if err != nil {
		return nil, err
	}

	var apiResp apiScanResults
	if err := json.Unmarshal(raw, &apiResp); err != nil {
		return nil, err
	}

	vulns := make([]Vulnerability, 0, len(apiResp.Vulnerabilities))
	for _, w := range apiResp.Vulnerabilities {
		v := Vulnerability{
			ID:                  w.Base.ID,
			Language:            w.Base.Language,
			Path:                w.Base.Path,
			VulnerableStartLine: w.Base.VulnerableStartLine,
			VulnerableEndLine:   w.Base.VulnerableEndLine,
			Details:             w.Base.Details,
			Branch:              w.Base.Branch,
		}
		// For SCA findings: base.vulnerability is null; populate from metadata/library.
		if v.Details.Name == "" && w.Metadata != nil {
			v.Details.Name = w.Metadata.Summary
			if v.Details.Name == "" {
				v.Details.Name = w.Metadata.GHSAID
			}
			v.Details.Description = w.Metadata.Details
			v.Details.Severity = strings.ToUpper(w.Base.CurrentSeverity)
			for _, c := range w.Metadata.CWEs {
				v.Details.CWE = append(v.Details.CWE, c.CweID)
			}
			if w.Library != nil {
				v.Language = w.Library.Ecosystem
				v.Path = w.Library.PackageName + "@" + w.Library.PackageVersion
			}
			// HowToPrevent: use autofix install command when available.
			if len(w.AutofixRecords) > 0 && w.AutofixRecords[0].InstallCommand != "" {
				v.Details.HowToPrevent = "Run: `" + w.AutofixRecords[0].InstallCommand + "`"
			} else if len(w.AutofixRecords) > 0 && w.AutofixRecords[0].RecommendedProposedVersion != "" {
				v.Details.HowToPrevent = "Update " + w.AutofixRecords[0].VulnerablePackage +
					" to version " + w.AutofixRecords[0].RecommendedProposedVersion + " or later."
			}
		}
		vulns = append(vulns, v)
	}

	return &ScanResults{
		ProjectID:       apiResp.ProjectID,
		ProjectName:     apiResp.ProjectName,
		Page:            apiResp.Page,
		Total:           apiResp.Total,
		TotalPages:      apiResp.TotalPages,
		Severity:        apiResp.Severity,
		Vulnerabilities: vulns,
	}, nil
}

// GetGroupedResults fetches one page of grouped results for the given scan type.
// Supported scan types: sast, iac, sca, secret, cicd.
func (c *Client) GetGroupedResults(projectID, scanType string, page, perPage int, branch string) (*GroupedScanResults, error) {
	q := url.Values{}
	q.Set("page", strconv.Itoa(page))
	q.Set("perPage", strconv.Itoa(perPage))
	q.Set("sort", "occurrenceCount")
	q.Set("order", "DESC")
	for _, s := range []string{"critical", "high", "medium", "low"} {
		q.Add("severityFilter[]", s)
	}
	for _, s := range []string{"to_verify", "confirmed"} {
		q.Add("statusFilter[]", s)
	}
	for _, s := range []string{"critical_urgent", "urgent", "normal", "low", "very_low"} {
		q.Add("priorityFilter[]", s)
	}
	if branch != "" {
		q.Set("branch", branch)
	}
	rawURL := fmt.Sprintf("%s/project/%s/results/%s/grouped?%s", c.APIURL, projectID, scanType, q.Encode())
	logger.Debug("GET %s", rawURL)

	raw, err := c.doGet(rawURL)
	if err != nil {
		return nil, err
	}

	var result GroupedScanResults
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetContainerGroupedResults fetches container images grouped by repository.
func (c *Client) GetContainerGroupedResults(projectID string, page, limit int, branch string) (*ContainerGroupedResults, error) {
	q := url.Values{}
	q.Set("page", strconv.Itoa(page))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("sort", "latestScanAt")
	q.Set("order", "DESC")
	if branch != "" {
		q.Set("branch", branch)
	}
	rawURL := fmt.Sprintf("%s/project/%s/results/container/images/grouped?%s", c.APIURL, projectID, q.Encode())
	logger.Debug("GET %s", rawURL)

	raw, err := c.doGet(rawURL)
	if err != nil {
		return nil, err
	}

	var result ContainerGroupedResults
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// doGet performs an authenticated GET request and returns the response body.
func (c *Client) doGet(rawURL string) ([]byte, error) {
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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}
