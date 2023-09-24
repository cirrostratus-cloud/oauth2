package client

import (
	util "github.com/cirrostratus-cloud/oauth2/util"
	"golang.org/x/crypto/bcrypt"
)

type CreateClientService struct {
	secretLenght    int
	clientRepostory ClientRepository
}

func (c CreateClientService) NewClient(redirectURI string) (Client, error) {
	secret, err := bcrypt.GenerateFromPassword(util.FromStringToByteArray(util.NewRandonSecret(c.secretLenght, c.isSecretUnique)), bcrypt.DefaultCost)
	if err != nil {
		return Client{}, err
	}
	client, err := NewClient(util.NewUUIDString(), util.FromByteArrayToString(secret), redirectURI)
	if err != nil {
		return client, err
	}
	client, err = c.clientRepostory.CreateClient(client)
	if err != nil {
		return client, err
	}
	return client, nil
}

func NewCreateClientService(secretLenght int, clientRepostory ClientRepository) CreateClientUseCase {
	return CreateClientService{secretLenght, clientRepostory}
}

func (c CreateClientService) isSecretUnique(secret string) (bool, error) {
	client, err := c.clientRepostory.FindClientBySecret(secret)
	if err != nil {
		return false, err
	}
	err = bcrypt.CompareHashAndPassword(util.FromStringToByteArray(client.GetSecret()), util.FromStringToByteArray(secret))
	if err != nil {
		return false, err
	}
	return (client.GetID() != ""), nil
}

type GetClientService struct {
	clientRepostory ClientRepository
}

func NewGetClientService(clientRepostory ClientRepository) GetClientUseCase {
	return GetClientService{clientRepostory}
}

func (c GetClientService) GetClientByID(clientID string) (Client, error) {
	if clientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	return c.clientRepostory.FindClientByID(clientID)
}

type DisableClientService struct {
	clientRepostory ClientRepository
}

func NewDisableClientService(clientRepostory ClientRepository) DisableClientUseCase {
	return DisableClientService{clientRepostory}
}

func (c DisableClientService) DisableClientByID(clientID string) (Client, error) {
	if clientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientID)
	if err != nil {
		return client, err
	}
	client.DisableClient()
	return c.clientRepostory.UpdateClient(client)
}

type EnableClientService struct {
	clientRepostory ClientRepository
}

func NewEnableClientService(clientRepostory ClientRepository) EnableClientUseCase {
	return EnableClientService{clientRepostory}
}

func (c EnableClientService) EnableClientByID(clientID string) (Client, error) {
	if clientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientID)
	if err != nil {
		return client, err
	}
	client.EnableClient()
	return c.clientRepostory.UpdateClient(client)
}

type AuthenticateClientService struct {
	clientRepostory ClientRepository
}

func NewAuthenticateClientService(clientRepostory ClientRepository) AuthenticateClientUseCase {
	return AuthenticateClientService{clientRepostory}
}

func (c AuthenticateClientService) AuthenticateClient(clientAuthentication ClientAuthentication) (Client, error) {
	if clientAuthentication.ClientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	if clientAuthentication.ClientSecret == "" {
		return Client{}, ErrClientSecretEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientAuthentication.ClientID)
	if err != nil {
		return client, err
	}
	if !client.IsEnabled() {
		return client, ErrClientDisabled
	}
	err = bcrypt.CompareHashAndPassword(util.FromStringToByteArray(client.GetSecret()), util.FromStringToByteArray(clientAuthentication.ClientSecret))
	if err != nil {
		return client, err
	}
	return client, nil
}
