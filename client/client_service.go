package client

import (
	"github.com/cirrostratus-cloud/common/uuid"
	util "github.com/cirrostratus-cloud/oauth2/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type CreateClientService struct {
	secretLenght           int
	clientRepostory        ClientRepository
	clientCreatedPublisher ClientCreatedPublisher
}

func (c CreateClientService) NewClient(createClient CreateClient) (Client, error) {
	log.WithFields(log.Fields{
		"redirectURIs": createClient.RedirectURIs,
	}).Info("Creating new client")
	secret, err := bcrypt.GenerateFromPassword(util.FromStringToByteArray(util.NewRandonSecret(c.secretLenght, c.isSecretUnique)), bcrypt.DefaultCost)
	if err != nil {
		return Client{}, err
	}
	client, err := NewClient(uuid.NewV4(), util.FromByteArrayToString(secret), createClient.RedirectURIs)
	if err != nil {
		return client, err
	}
	client, err = c.clientRepostory.CreateClient(client)
	if err != nil {
		return client, err
	}
	err = c.clientCreatedPublisher.ClientCreated(ClientCreatedEvent{
		ClientID: client.GetID(),
	})
	if err != nil {
		err = c.clientRepostory.DeleteClientByID(client.GetID())
		return Client{}, err
	}
	return client, nil
}

func NewCreateClientService(secretLenght int, clientRepostory ClientRepository, clientCreatedPublisher ClientCreatedPublisher) CreateClientUseCase {
	return CreateClientService{
		secretLenght:           secretLenght,
		clientRepostory:        clientRepostory,
		clientCreatedPublisher: clientCreatedPublisher,
	}
}

func (c CreateClientService) isSecretUnique(secret string) (bool, error) {
	// FIXME: Add logs
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

func (c GetClientService) GetClientByID(clientByID ClientByID) (Client, error) {
	// FIXME: Add logs
	if clientByID.ClientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	return c.clientRepostory.FindClientByID(clientByID.ClientID)
}

type DisableClientService struct {
	clientRepostory         ClientRepository
	clientDisabledPublisher ClientDisabledPublisher
}

func NewDisableClientService(clientRepostory ClientRepository, clientDisabledPublisher ClientDisabledPublisher) DisableClientUseCase {
	return DisableClientService{
		clientRepostory,
		clientDisabledPublisher}
}

func (c DisableClientService) DisableClientByID(clientByID ClientByID) (Client, error) {
	// FIXME: Add logs
	if clientByID.ClientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientByID.ClientID)
	if err != nil {
		return client, err
	}
	client.DisableClient()
	client, err = c.clientRepostory.UpdateClient(client)
	if err != nil {
		client.EnableClient()
		client, err = c.clientRepostory.UpdateClient(client)
		return client, err
	}
	return client, nil
}

type EnableClientService struct {
	clientRepostory       ClientRepository
	clientEnablePublisher ClientEnabledPublisher
}

func NewEnableClientService(clientRepostory ClientRepository, clientEnablePublisher ClientEnabledPublisher) EnableClientUseCase {
	return EnableClientService{
		clientRepostory:       clientRepostory,
		clientEnablePublisher: clientEnablePublisher,
	}
}

func (c EnableClientService) EnableClientByID(clientByID ClientByID) (Client, error) {
	// FIXME: Add logs
	if clientByID.ClientID == "" {
		return Client{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientByID.ClientID)
	if err != nil {
		return client, err
	}
	client.EnableClient()
	client, err = c.clientRepostory.UpdateClient(client)
	if err != nil {
		client.DisableClient()
		client, err = c.clientRepostory.UpdateClient(client)
		return client, err
	}
	return client, nil
}

type AuthenticateClientService struct {
	clientRepostory ClientRepository
}

func NewAuthenticateClientService(clientRepostory ClientRepository) AuthenticateClientUseCase {
	return AuthenticateClientService{clientRepostory}
}

func (c AuthenticateClientService) AuthenticateClient(clientAuthentication ClientAuthentication) (Client, error) {
	// FIXME: Add logs
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
