package api

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func (c *Client) GetResults(scanID string) (string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/results/%s", c.APIURL, scanID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		responseBody, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("API error: %s", responseBody)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
