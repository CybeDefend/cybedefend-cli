package api

import (
	"bytes"
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ContainerScanRequest represents the request body for a container scan.
type ContainerScanRequest struct {
	CredentialID string   `json:"credentialId,omitempty"`
	ImageName    string   `json:"imageName"`
	Branch       string   `json:"branch,omitempty"`
	PrivateScan  *bool    `json:"privateScan,omitempty"`
	Severities   []string `json:"severities,omitempty"`
}

// ContainerScanResponse represents the response from a container scan start.
type ContainerScanResponse struct {
	Success           bool     `json:"success"`
	Message           string   `json:"message"`
	ScanID            string   `json:"scanId,omitempty"`
	DetectedLanguages []string `json:"detectedLanguages,omitempty"`
}

// RegistryType represents a supported container registry.
type RegistryType string

const (
	RegistryGitLab    RegistryType = "gitlab"
	RegistryGitHub    RegistryType = "github-container-registry"
	RegistryDockerHub RegistryType = "dockerhub"
	RegistryGCR       RegistryType = "gcr"
	RegistryECR       RegistryType = "ecr"
	RegistryACR       RegistryType = "acr"
	RegistryQuay      RegistryType = "quay"
	RegistryHarbor    RegistryType = "harbor"
	RegistryJFrog     RegistryType = "jfrog"
)

// registryPathMap maps registry types to their API path segments.
var registryPathMap = map[RegistryType]string{
	RegistryGitLab:    "integrations/gitlab/container-registry",
	RegistryGitHub:    "integrations/github-container-registry",
	RegistryDockerHub: "integrations/dockerhub/container-registry",
	RegistryGCR:       "integrations/gcr/container-registry",
	RegistryECR:       "integrations/ecr/container-registry",
	RegistryACR:       "integrations/acr/container-registry",
	RegistryQuay:      "integrations/quay/container-registry",
	RegistryHarbor:    "integrations/harbor/container-registry",
	RegistryJFrog:     "integrations/jfrog/container-registry",
}

// StartContainerScan starts a container scan for the given registry type.
func (c *Client) StartContainerScan(registry RegistryType, projectID string, reqBody *ContainerScanRequest) (*ContainerScanResponse, error) {
	pathSegment, ok := registryPathMap[registry]
	if !ok {
		return nil, fmt.Errorf("unsupported registry type: %s", registry)
	}

	apiURL := fmt.Sprintf("%s/%s/project/%s/scan", c.APIURL, pathSegment, projectID)
	logger.Debug("POST %s", apiURL)

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	token, err := c.GetAccessToken()
	if err != nil {
		return nil, fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	logger.Debug("HTTP Status: %d", resp.StatusCode)
	logger.Debug("Response Body: %s", string(respBody))

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result ContainerScanResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &result, nil
}
