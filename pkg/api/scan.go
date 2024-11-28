package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

type ScanResult struct {
	Success           bool     `json:"success"`
	ScanID            string   `json:"scanId"`
	Message           string   `json:"message"`
	DetectedLanguages []string `json:"detectedLanguages"`
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
