package api

import (
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// StartScanResponse represents the response from the scan start endpoint
type StartScanResponse struct {
	URL    string `json:"url"`
	ScanID string `json:"scanId"`
}

// GetScanID returns the scan ID
func (s *StartScanResponse) GetScanID() string { return s.ScanID }

// ScanStatus represents the status of a scan
type ScanStatus struct {
	ID                    string          `json:"id"`
	Name                  string          `json:"name"`
	State                 string          `json:"state"`
	Language              []string        `json:"language"`
	ProjectID             string          `json:"projectId"`
	Private               bool            `json:"private"`
	InitializerUserID     string          `json:"initializerUserId"`
	CreateAt              string          `json:"createAt"`
	UpdatedAt             string          `json:"updatedAt"`
	ScanType              string          `json:"scanType"`
	StartTime             string          `json:"startTime"`
	EndTime               string          `json:"endTime"`
	Containers            []ScanContainer `json:"containers"`
	Progress              int             `json:"progress"`
	Step                  string          `json:"step"`
	VulnerabilityDetected int             `json:"vulnerabilityDetected"`
}

// ScanContainer represents a container used in the scan
type ScanContainer struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	CreatedAt  string `json:"createdAt"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	ScanID     string `json:"scanId"`
}

// IsCompleted checks if the scan is completed
func (s *ScanStatus) IsCompleted() bool {
	completedStates := []string{"completed", "completed_degraded", "failed"}
	for _, state := range completedStates {
		if s.State == state {
			return true
		}
	}
	return false
}

// IsFailed checks if the scan failed
func (s *ScanStatus) IsFailed() bool {
	return s.State == "failed"
}

// StartScanRequest represents the request body for starting a scan
type StartScanRequest struct {
	Branch string `json:"branch,omitempty"`
}

// StartScan initiates a scan, uploads the file to the provided pre-signed URL, and returns the scan ID.
func (c *Client) StartScan(projectID, filePath, branch string) (*StartScanResponse, error) {
	// Step 1: call start endpoint to get upload URL and scanId
	startURL := fmt.Sprintf("%s/project/%s/scan/start", c.APIURL, projectID)
	logger.Debug("POST %s", startURL)

	// Prepare request body with branch if provided
	var reqBody io.Reader
	if branch != "" {
		reqData := StartScanRequest{Branch: branch}
		jsonData, err := json.Marshal(reqData)
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %w", err)
		}
		reqBody = strings.NewReader(string(jsonData))
		logger.Debug("Request Body: %s", string(jsonData))
	}

	req, err := http.NewRequest("POST", startURL, reqBody)
	if err != nil {
		return nil, err
	}
	token, err := c.GetAccessToken()
	if err != nil {
		return nil, fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if branch != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	logger.Debug("HTTP Status: %d", resp.StatusCode)
	logger.Debug("Response Body: %s", string(responseBody))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d - response: %s", resp.StatusCode, string(responseBody))
	}

	var startResp StartScanResponse
	if err := json.Unmarshal(responseBody, &startResp); err != nil {
		return nil, fmt.Errorf("error parsing start response: %w", err)
	}
	if startResp.URL == "" || startResp.ScanID == "" {
		return nil, fmt.Errorf("invalid start response: missing url or scanId")
	}

	// Step 2: upload the zip file via PUT to the pre-signed URL
	if err := uploadFileToURL(startResp.URL, filePath); err != nil {
		return nil, fmt.Errorf("upload failed: %w", err)
	}

	return &startResp, nil
}

// progressReader wraps an io.Reader and reports progress
type progressReader struct {
	reader      io.Reader
	total       int64
	current     int64
	lastPercent int
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.current += int64(n)

	// Calculate percentage
	percent := int(float64(pr.current) / float64(pr.total) * 100)

	// Only log if percentage changed and is a multiple of 10 (or 100%)
	if percent != pr.lastPercent && (percent%10 == 0 || percent == 100) {
		logger.Info("Upload progress: %d%%", percent)
		pr.lastPercent = percent
	}

	return n, err
}

// uploadFileToURL uploads the file at filePath to the given pre-signed URL using PUT.
func uploadFileToURL(uploadURL, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	// Avoid leaking signed query params in logs
	loggedURL := uploadURL
	if q := strings.Index(loggedURL, "?"); q != -1 {
		loggedURL = loggedURL[:q] + "?(signed)"
	}

	logger.Info("Uploading file (%.2f MB)...", float64(stat.Size())/(1024*1024))
	logger.Debug("PUT %s (size: %d bytes)", loggedURL, stat.Size())

	// Create progress reader
	progressR := &progressReader{
		reader:      file,
		total:       stat.Size(),
		current:     0,
		lastPercent: -1,
	}

	req, err := http.NewRequest("PUT", uploadURL, progressR)
	if err != nil {
		return err
	}

	// Set Content-Type for all uploads
	req.Header.Set("Content-Type", "application/zip")

	// Set additional headers for Google Cloud Storage signed URLs
	if strings.Contains(uploadURL, "storage.googleapis.com") {
		req.Header.Set("x-goog-if-generation-match", "0")
		req.Header.Set("x-goog-content-length-range", "0,5368709120")
	}

	// Ensure content length is set when possible
	req.ContentLength = stat.Size()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	logger.Debug("Upload HTTP Status: %d", resp.StatusCode)
	if len(body) > 0 {
		logger.Debug("Upload Response Body: %s", string(body))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("upload unexpected status code: %d - response: %s", resp.StatusCode, string(body))
	}

	logger.Success("Upload completed successfully")
	return nil
}

// GetScanStatus retrieves the status of a scan
func (c *Client) GetScanStatus(projectID, scanID string) (*ScanStatus, error) {
	url := fmt.Sprintf("%s/project/%s/scan/%s", c.APIURL, projectID, scanID)

	logger.Debug("GET %s", url)

	req, err := http.NewRequest("GET", url, nil)
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

	// Read the response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Log HTTP status and response body
	logger.Debug("HTTP Status: %d", resp.StatusCode)
	logger.Debug("Response Body: %s", string(responseBody))

	// Check for non-2XX status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status code: %d - response: %s", resp.StatusCode, string(responseBody))
	}

	// Parse the JSON response
	var result ScanStatus
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &result, nil
}

// liveVulnerabilityStates excludes the findings a severity gate must not block
// a build for: someone has already ruled on them.
func isLiveVulnerability(state string) bool {
	switch strings.ToLower(state) {
	case "resolved", "not_exploitable", "ignored":
		return false
	}
	return true
}

// CountVulnerabilitiesBySeverity counts a branch's live vulnerabilities, grouped
// by severity, across every scan type.
//
// It decodes through GetResults rather than reading the JSON as a bare map. The
// API nests each finding under a "base" object, so reading `currentSeverity` at
// the top level silently matched nothing: every finding was skipped, the counts
// came back empty and `--break-on-severity` reported a clean build for a project
// whose policy evaluation was blocking on 13 criticals. A gate that fails open
// is worse than no gate, because CI is built to trust it.
//
// The scan type is not fixed either — a critical CVE in a dependency has to
// block a build the same way a critical SAST finding does — and the pages are
// walked to the end, since the first page is not the whole result set.
func (c *Client) CountVulnerabilitiesBySeverity(projectID, branch string, severities []string) (map[string]int, error) {
	wanted := make(map[string]bool, len(severities))
	for _, severity := range severities {
		wanted[strings.ToLower(severity)] = true
	}

	counts := make(map[string]int)
	for _, scanType := range ValidScanTypes {
		if scanType == "all" {
			continue
		}
		if err := c.countScanType(projectID, scanType, branch, wanted, counts); err != nil {
			return nil, err
		}
	}
	return counts, nil
}

const (
	severityCountPageSize = 100
	// A guard against paging forever if the API keeps reporting more pages.
	severityCountMaxPages = 100
)

func (c *Client) countScanType(projectID, scanType, branch string, wanted map[string]bool, counts map[string]int) error {
	for page := 1; page <= severityCountMaxPages; page++ {
		results, err := c.GetResults(projectID, scanType, page, severityCountPageSize, branch, nil)
		if err != nil {
			// A scan type the plan does not cover answers 403. That is not a
			// reason to abandon the gate for the types it does cover.
			if strings.Contains(err.Error(), "403") {
				logger.Debug("skipping %s for the severity gate: %v", scanType, err)
				return nil
			}
			return fmt.Errorf("counting %s vulnerabilities: %w", scanType, err)
		}

		for _, v := range results.Vulnerabilities {
			if !isLiveVulnerability(v.CurrentState) {
				continue
			}
			severity := strings.ToLower(v.CurrentSeverity)
			if wanted[severity] {
				counts[severity]++
			}
		}

		if results.TotalPages <= page || len(results.Vulnerabilities) == 0 {
			return nil
		}
	}
	return nil
}
