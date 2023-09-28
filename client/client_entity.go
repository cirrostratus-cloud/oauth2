package client

import (
	"errors"

	"github.com/cirrostratus-cloud/oauth2/util"
)

var ErrClientAccessTokenNotFound = errors.New("client access token not found")
var ErrClientRefreshTokenNotFound = errors.New("client refresh token not found")

type Client struct {
	id                  string
	secret              string
	enabled             bool
	redirectURI         string
	clientAccessTokens  []ClientAccessToken
	clientRefreshTokens []ClientRefreshToken
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

func (c Client) GetClientAccessTokens() []ClientAccessToken {
	return c.clientAccessTokens
}

func (c *Client) AddClientAccessToken(id string, accessTokenID string) ClientAccessToken {
	clientAccessToken := ClientAccessToken{
		id:            id,
		clientID:      c.id,
		accessTokenID: accessTokenID,
	}
	c.clientAccessTokens = append(c.clientAccessTokens, clientAccessToken)
	return clientAccessToken
}

func (c *Client) RemoveClientAccessToken(clientAccessToken ClientAccessToken) error {
	for i, v := range c.clientAccessTokens {
		if v.GetID() == clientAccessToken.GetID() {
			c.clientAccessTokens = append(c.clientAccessTokens[:i], c.clientAccessTokens[i+1:]...)
			return nil
		}
	}
	return ErrClientAccessTokenNotFound
}

func (c Client) GetClientAccessTokenByID(id string) (ClientAccessToken, error) {
	for _, v := range c.clientAccessTokens {
		if v.GetID() == id {
			return v, nil
		}
	}
	return ClientAccessToken{}, ErrClientAccessTokenNotFound
}

func (c Client) GetClientRefreshTokens() []ClientRefreshToken {
	return c.clientRefreshTokens
}

func (c *Client) AddClientRefreshToken(id string, refreshTokenID string) ClientRefreshToken {
	clientRefreshToken := newClientRefreshToken(id, c.id, refreshTokenID)
	c.clientRefreshTokens = append(c.clientRefreshTokens, clientRefreshToken)
	return clientRefreshToken
}

func (c *Client) RemoveClientRefreshToken(clientRefreshToken ClientRefreshToken) error {
	for i, v := range c.clientRefreshTokens {
		if v.GetID() == clientRefreshToken.GetID() {
			c.clientRefreshTokens = append(c.clientRefreshTokens[:i], c.clientRefreshTokens[i+1:]...)
			return nil
		}
	}
	return ErrClientRefreshTokenNotFound
}

func (c Client) GetClientRefreshTokenByID(id string) (ClientRefreshToken, error) {
	for _, v := range c.clientRefreshTokens {
		if v.GetID() == id {
			return v, nil
		}
	}
	return ClientRefreshToken{}, ErrClientRefreshTokenNotFound
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

// ClientAccessToken is a struct to represent client access token
type ClientAccessToken struct {
	id            string
	clientID      string
	accessTokenID string
}

// Function to get client id from client access token
func (a ClientAccessToken) GetClientID() string {
	return a.clientID
}

// Function to get access token id from client access token
func (a ClientAccessToken) GetAccessTokenID() string {
	return a.accessTokenID
}

// Function to get client access token id
func (a ClientAccessToken) GetID() string {
	return a.id
}

type ClientRefreshToken struct {
	id             string
	clientID       string
	refreshTokenID string
}

func (r ClientRefreshToken) GetClientID() string {
	return r.clientID
}

func (r ClientRefreshToken) GetRefreshTokenID() string {
	return r.refreshTokenID
}

func (r ClientRefreshToken) GetID() string {
	return r.id
}

func newClientRefreshToken(id string, clientID string, refreshTokenID string) ClientRefreshToken {
	return ClientRefreshToken{id: id, clientID: clientID, refreshTokenID: refreshTokenID}
}
