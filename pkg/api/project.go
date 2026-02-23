package api

import (
	"bytes"
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Project represents a CybeDefend project.
type Project struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	TeamID                  string   `json:"teamId"`
	OrganizationID          string   `json:"organizationId"`
	AIMergeRequestEnabled   bool     `json:"aiMergeRequestEnabled"`
	ImprovingResultsEnabled bool     `json:"improvingResultsEnabled"`
	AutoFixEnabled          bool     `json:"autoFixEnabled"`
	Language                []string `json:"language"`
	CreatedAt               string   `json:"createdAt"`
	UpdatedAt               string   `json:"updatedAt"`
}

// CreateProjectRequest represents the body for creating a project.
type CreateProjectRequest struct {
	Name                    string `json:"name"`
	AIMergeRequestEnabled   *bool  `json:"aiMergeRequestEnabled,omitempty"`
	ImprovingResultsEnabled *bool  `json:"improvingResultsEnabled,omitempty"`
	AutoFixEnabled          *bool  `json:"autoFixEnabled,omitempty"`
}

// CreateProject creates a new project under the given team.
func (c *Client) CreateProject(teamID string, reqBody *CreateProjectRequest) (*Project, error) {
	apiURL := fmt.Sprintf("%s/team/%s/project", c.APIURL, teamID)
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

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var project Project
	if err := json.Unmarshal(respBody, &project); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// The create endpoint returns "projectId" instead of "id"
	if project.ID == "" {
		var raw map[string]interface{}
		if err := json.Unmarshal(respBody, &raw); err == nil {
			if pid, ok := raw["projectId"].(string); ok {
				project.ID = pid
			}
		}
	}

	return &project, nil
}

// DeleteProject deletes a project by ID.
func (c *Client) DeleteProject(projectID string) error {
	apiURL := fmt.Sprintf("%s/project/%s", c.APIURL, projectID)
	logger.Debug("DELETE %s", apiURL)

	req, err := http.NewRequest("DELETE", apiURL, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	token, err := c.GetAccessToken()
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	logger.Debug("HTTP Status: %d", resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// GetProject retrieves a project by ID.
func (c *Client) GetProject(projectID string) (*Project, error) {
	apiURL := fmt.Sprintf("%s/project/%s", c.APIURL, projectID)
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

	var project Project
	if err := json.Unmarshal(respBody, &project); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Some endpoints return "projectId" instead of "id"
	if project.ID == "" {
		var raw map[string]interface{}
		if err := json.Unmarshal(respBody, &raw); err == nil {
			if pid, ok := raw["projectId"].(string); ok {
				project.ID = pid
			}
		}
	}

	return &project, nil
}
