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

// StartScan initiates a scan, uploads the file to the provided pre-signed URL, and returns the scan ID.
func (c *Client) StartScan(projectID, filePath string) (*StartScanResponse, error) {
	// Step 1: call start endpoint to get upload URL and scanId
	startURL := fmt.Sprintf("%s/project/%s/scan/start", c.APIURL, projectID)
	logger.Debug("POST %s", startURL)

	req, err := http.NewRequest("POST", startURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", c.APIKey)

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

	req, err := http.NewRequest("PUT", uploadURL, file)
	if err != nil {
		return err
	}

	// Set headers only for Google Cloud Storage signed URLs
	if strings.Contains(uploadURL, "storage.googleapis.com") {
		req.Header.Set("Content-Type", "application/zip")
		req.Header.Set("x-goog-if-generation-match", "0")
		req.Header.Set("x-goog-content-length-range", "0,5368709120")
	}

	// Ensure content length is set when possible
	req.ContentLength = stat.Size()

	// Avoid leaking signed query params in logs
	loggedURL := uploadURL
	if q := strings.Index(loggedURL, "?"); q != -1 {
		loggedURL = loggedURL[:q] + "?(signed)"
	}
	logger.Debug("PUT %s (size: %d bytes)", loggedURL, stat.Size())
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
	req.Header.Set("x-api-key", c.APIKey)

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

// GetVulnerabilitiesBySeverity returns the count of vulnerabilities for each severity
func (c *Client) GetVulnerabilitiesBySeverity(projectID, scanType string, severities []string) (map[string]int, error) {
	// Build the URL with query parameters
	url := fmt.Sprintf("%s/project/%s/results/%s?pageNumber=1&sort=currentSeverity&order=asc", c.APIURL, projectID, scanType)

	// Add severity parameters
	for _, severity := range severities {
		url = fmt.Sprintf("%s&severity[]=%s", url, severity)
	}

	// Add the status parameters - we only want vulnerabilities that are not resolved or not_exploitable
	url = fmt.Sprintf("%s&status[]=to_verify&status[]=confirmed", url)

	// Add the priority parameters
	url = fmt.Sprintf("%s&priority[]=critical_urgent&priority[]=urgent&priority[]=normal&priority[]=low&priority[]=very_low", url)

	logger.Debug("GET %s", url)

	req, err := http.NewRequest("GET", url, nil)
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

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the response to extract vulnerabilities by severity
	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}

	// Count vulnerabilities by severity
	severityCount := make(map[string]int)
	if vulnerabilities, ok := result["vulnerabilities"].([]interface{}); ok {
		for _, vuln := range vulnerabilities {
			if vulnMap, ok := vuln.(map[string]interface{}); ok {
				// Only count vulnerabilities that are not resolved or not_exploitable
				state, _ := vulnMap["currentState"].(string)
				if state != "resolved" && state != "not_exploitable" {
					severity := strings.ToLower(vulnMap["currentSeverity"].(string))
					severityCount[severity]++
				}
			}
		}
	}

	return severityCount, nil
}
