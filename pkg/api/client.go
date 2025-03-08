package api

type Client struct {
	APIURL string
	APIKey string
}

func NewClient(apiURL, apiKey string) *Client {
	return &Client{
		APIURL: apiURL,
		APIKey: apiKey,
	}
}
