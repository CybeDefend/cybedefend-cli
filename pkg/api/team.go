package api

import (
	"bytes"
	"cybedefend-cli/pkg/logger"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// Team represents a CybeDefend team.
type Team struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

// CreateTeamRequest represents the body for creating a team.
type CreateTeamRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CreateTeamResponse represents the response from creating a team.
type CreateTeamResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	OrganizationID string `json:"organizationId"`
	TeamID         string `json:"teamId"`
	Name           string `json:"name"`
	Description    string `json:"description"`
}

// UpdateTeamRequest represents the body for updating a team.
type UpdateTeamRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// UpdateTeamResponse represents the response from updating a team.
type UpdateTeamResponse struct {
	Message     string `json:"message"`
	UpdatedTeam Team   `json:"updatedTeam"`
}

// TeamMember represents a member in a team.
type TeamMember struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Avatar    string `json:"avatar,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
}

// TeamMembersResponse represents the paginated team members response.
type TeamMembersResponse struct {
	Users      []TeamMember `json:"users"`
	TotalUsers int          `json:"totalUsers"`
	TotalPages int          `json:"totalPages"`
}

// AddTeamMemberRequest represents the body for adding a team member.
type AddTeamMemberRequest struct {
	UserID string `json:"userId"`
	Role   string `json:"role"` // team_manager, analyst_developer, developer, read_only
}

// UpdateMemberRoleRequest represents the body for updating a member's role.
type UpdateMemberRoleRequest struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// RemoveTeamMemberRequest represents the body for removing a team member.
type RemoveTeamMemberRequest struct {
	UserID string `json:"userId"`
}

// CreateTeam creates a new team in an organization.
func (c *Client) CreateTeam(organizationID string, reqBody *CreateTeamRequest) (*CreateTeamResponse, error) {
	apiURL := fmt.Sprintf("%s/organization/%s/team", c.APIURL, organizationID)
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result CreateTeamResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &result, nil
}

// DeleteTeam deletes a team by ID.
func (c *Client) DeleteTeam(teamID string) error {
	apiURL := fmt.Sprintf("%s/team/%s", c.APIURL, teamID)
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

// GetTeam retrieves a team by organization ID and team ID.
func (c *Client) GetTeam(organizationID, teamID string) (*Team, error) {
	apiURL := fmt.Sprintf("%s/organization/%s/team/%s", c.APIURL, organizationID, teamID)
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

	var team Team
	if err := json.Unmarshal(respBody, &team); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &team, nil
}

// GetAllTeams retrieves all teams for an organization.
func (c *Client) GetAllTeams(organizationID string) ([]Team, error) {
	apiURL := fmt.Sprintf("%s/organization/%s/teams", c.APIURL, organizationID)
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

	var teamsWrapper struct {
		Teams []Team `json:"teams"`
	}
	if err := json.Unmarshal(respBody, &teamsWrapper); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return teamsWrapper.Teams, nil
}

// UpdateTeam updates a team by ID.
func (c *Client) UpdateTeam(teamID string, reqBody *UpdateTeamRequest) (*UpdateTeamResponse, error) {
	apiURL := fmt.Sprintf("%s/team/%s", c.APIURL, teamID)
	logger.Debug("PUT %s", apiURL)

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("PUT", apiURL, bytes.NewReader(body))
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result UpdateTeamResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &result, nil
}

// GetTeamMembers retrieves paginated team members.
func (c *Client) GetTeamMembers(teamID string, page, pageSize int, search string) (*TeamMembersResponse, error) {
	q := url.Values{}
	if page > 0 {
		q.Set("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Set("pageSize", strconv.Itoa(pageSize))
	}
	if search != "" {
		q.Set("search", search)
	}

	apiURL := fmt.Sprintf("%s/team/%s/members?%s", c.APIURL, teamID, q.Encode())
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

	var result TeamMembersResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	return &result, nil
}

// AddTeamMember adds a user to a team.
func (c *Client) AddTeamMember(teamID string, reqBody *AddTeamMemberRequest) error {
	apiURL := fmt.Sprintf("%s/team/%s/member", c.APIURL, teamID)
	logger.Debug("POST %s", apiURL)

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	token, err := c.GetAccessToken()
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

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

// UpdateMemberRole updates a team member's role.
func (c *Client) UpdateMemberRole(teamID string, reqBody *UpdateMemberRoleRequest) error {
	apiURL := fmt.Sprintf("%s/team/%s/member/role", c.APIURL, teamID)
	logger.Debug("PUT %s", apiURL)

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("PUT", apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	token, err := c.GetAccessToken()
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

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

// RemoveTeamMember removes a user from a team.
func (c *Client) RemoveTeamMember(teamID string, userID string) error {
	apiURL := fmt.Sprintf("%s/team/%s/member", c.APIURL, teamID)
	logger.Debug("DELETE %s", apiURL)

	body, err := json.Marshal(&RemoveTeamMemberRequest{UserID: userID})
	if err != nil {
		return fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("DELETE", apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	token, err := c.GetAccessToken()
	if err != nil {
		return fmt.Errorf("authentication error: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

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
