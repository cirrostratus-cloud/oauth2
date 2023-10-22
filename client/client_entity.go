package client

import (
	"errors"

	"github.com/cirrostratus-cloud/oauth2/util"
	log "github.com/sirupsen/logrus"
)

var ErrClientAccessTokenNotFound = errors.New("client access token not found")
var ErrClientRefreshTokenNotFound = errors.New("client refresh token not found")
var ErrRedirectURISEmpty = errors.New("redirect URIs is empty")

type Client struct {
	id           string
	secret       string
	enabled      bool
	redirectURIs []string
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

func (c Client) GetRedirectURIs() []string {
	return c.redirectURIs
}

func (c *Client) UpdateRedirectURIs(redirectURIs []string) {
	c.redirectURIs = redirectURIs
}

func (c Client) ExistsRedirectURI(redirectURI string) bool {
	for _, uri := range c.redirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

func NewClient(clientID string, secret string, redirectURIs []string) (Client, error) {
	if clientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	if secret == "" {
		return Client{}, ErrClientSecretEmpty
	}

	if len(redirectURIs) == 0 {
		log.WithFields(log.Fields{
			"redirectURIs": redirectURIs,
		}).Warn("Redirect URIs is empty")
		return Client{}, ErrRedirectURISEmpty
	}

	for _, redirectURI := range redirectURIs {
		if redirectURI == "" {
			return Client{}, ErrClientRedirectURIEmpty
		}
		if err := util.ValidateHTTPURL(redirectURI); err != nil {
			return Client{}, err
		}
	}

	return Client{id: clientID, secret: secret, enabled: true, redirectURIs: redirectURIs}, nil
}
