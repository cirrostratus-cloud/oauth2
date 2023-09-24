package client

type Client struct {
	id          string
	secret      string
	clientType  ClientType
	enabled     bool
	redirectURI string
}

func (c Client) GetID() string {
	return c.id
}

func (c Client) GetSecret() string {
	return c.secret
}

func (c Client) GetType() ClientType {
	return c.clientType
}

func (c Client) IsPublic() bool {
	return c.clientType == ClientTypePublic
}

func (c Client) IsEnabled() bool {
	return c.enabled
}

func (c *Client) DisableClient() {
	c.enabled = false
}

func (c *Client) EnableClient() {
	c.enabled = true
}

func (c Client) GetRedirectURI() string {
	return c.redirectURI
}

func NewClient(clientID string, secret string, clientType ClientType, redirectURI string) Client {
	return Client{id: clientID, secret: secret, clientType: clientType, enabled: true, redirectURI: redirectURI}
}
