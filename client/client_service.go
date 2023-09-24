package client

import (
	"errors"

	util "github.com/cirrostratus-cloud/oauth2/util"
)

type CreateClientService struct {
	secretLenght    int
	clientRepostory ClientRepository
}

func (c CreateClientService) NewClient(isPublic bool, redirectUri string) (Client, error) {
	clientType := ClientTypeConfidential
	if isPublic {
		clientType = ClientTypePublic
	}
	// TODO: Check if redirectUri is valid
	client := NewClient(util.NewUUIDString(), util.NewRandonSecret(c.secretLenght, c.isSecretUnique), clientType, redirectUri) // TODO: Use Bcrypt to hash secret
	return c.clientRepostory.CreateClient(client)
}

func (c CreateClientService) isSecretUnique(secret string) bool {
	client, err := c.clientRepostory.FindClientBySecret(secret)
	return client.GetSecret() == secret && err == nil // TODO: Use Bcrypt to compare secrets
}

func NewCreateClientService(secretLenght int, clientRepostory ClientRepository) CreateClientUseCase {
	return CreateClientService{secretLenght, clientRepostory}
}

type GetClientService struct {
	clientRepostory ClientRepository
}

func (c GetClientService) GetClientByID(clientID string) (Client, error) {
	if clientID == "" {
		return Client{}, errors.New("Client ID is empty")
	}
	return c.clientRepostory.FindClientByID(clientID)
}

func NewGetClientService(clientRepostory ClientRepository) GetClientUseCase {
	return GetClientService{clientRepostory}
}

type DisableClientService struct {
	clientRepostory ClientRepository
}

func (c DisableClientService) DisableClientByID(clientID string) (Client, error) {
	client, err := c.clientRepostory.FindClientByID(clientID)
	if err != nil {
		return client, err
	}
	client.DisableClient()
	return c.clientRepostory.UpdateClient(client)
}

func NewDisableClientService(clientRepostory ClientRepository) DisableClientUseCase {
	return DisableClientService{clientRepostory}
}

type EnableClientService struct {
	clientRepostory ClientRepository
}

func (c EnableClientService) EnableClientByID(clientID string) (Client, error) {
	client, err := c.clientRepostory.FindClientByID(clientID)
	if err != nil {
		return client, err
	}
	client.EnableClient()
	return c.clientRepostory.UpdateClient(client)
}

func NewEnableClientService(clientRepostory ClientRepository) EnableClientUseCase {
	return EnableClientService{clientRepostory}
}

type AuthenticateClientService struct {
	clientRepostory ClientRepository
}

func (c AuthenticateClientService) AuthenticateClient(clientAuthentication ClientAuthentication) (Client, error) {
	client, err := c.clientRepostory.FindClientByID(clientAuthentication.ClientID)
	if err != nil {
		return client, err
	}
	if client.GetSecret() != clientAuthentication.ClientSecret { // TODO: Use Bcrypt to compare secrets
		return client, errors.New("Client authentication failed")
	}
	return client, nil
}

func NewAuthenticateClientService(clientRepostory ClientRepository) AuthenticateClientUseCase {
	return AuthenticateClientService{clientRepostory}
}
