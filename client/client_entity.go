package client

import (
	"github.com/cirrostratus-cloud/oauth2/util"
)

type Client struct {
	id          string
	secret      string
	enabled     bool
	redirectURI string
}

func (c Client) GetID() string {
	return c.id
}

func (c Client) GetSecret() string {
	return c.secret
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

func NewClient(clientID string, secret string, redirectURI string) (Client, error) {
	if clientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	if secret == "" {
		return Client{}, ErrClientSecretEmpty
	}

	if err := util.ValidateHTTPURL(redirectURI); err != nil {
		return Client{}, err
	}

	return Client{id: clientID, secret: secret, enabled: true, redirectURI: redirectURI}, nil
}
