package api

import (
	"bytes"
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type ScanResult struct {
	Success           bool     `json:"success"`
	ScanID            string   `json:"scanId"`
	Message           string   `json:"message"`
	DetectedLanguages []string `json:"detectedLanguages"`
}

// GetScanID returns the scan ID from either the ScanID field or the Message field
func (s *ScanResult) GetScanID() string {
	if s.ScanID != "" {
		return s.ScanID
	}
	// If ScanID is empty, use Message field which now contains the scan ID
	return s.Message
}

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

func (c *Client) StartScan(projectID, filePath string) (*ScanResult, error) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Prepare the multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("scan", filepath.Base(filePath))
	if err != nil {
		return nil, err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	// Build the URL with projectID
	url := fmt.Sprintf("%s/project/%s/scan/start", c.APIURL, projectID)

	logger.Debug("POST %s", url)

	// Create the HTTP request
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("x-api-key", c.APIKey)

	// Send the request
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
	var result ScanResult
	err = json.Unmarshal(responseBody, &result)
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Check if the API call was successful
	if !result.Success {
		return nil, fmt.Errorf("%s", result.Message)
	}

	// Return the ScanResult
	return &result, nil
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
