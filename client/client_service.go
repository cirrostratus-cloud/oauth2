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
	log.WithFields(log.Fields{
		"clientID": client.GetID(),
	}).Info("Client created")
	err = c.clientCreatedPublisher.ClientCreated(ClientCreatedEvent{
		ClientID: client.GetID(),
	})
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": client.GetID(),
		}).Error("Error publishing client created event")
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
	client, err := c.clientRepostory.FindClientBySecret(secret)
	if err != nil {
		return false, err
	}
	if client.GetID() != "" {
		log.Warn("Client secret already exists")
		return false, nil
	}
	err = bcrypt.CompareHashAndPassword(util.FromStringToByteArray(client.GetSecret()), util.FromStringToByteArray(secret))
	if err != nil {
		return false, err
	}
	return true, nil
}

type GetClientService struct {
	clientRepostory ClientRepository
}

func NewGetClientService(clientRepostory ClientRepository) GetClientUseCase {
	return GetClientService{clientRepostory}
}

func (c GetClientService) GetClientByID(clientByID ClientByID) (Client, error) {
	log.WithFields(log.Fields{
		"clientID": clientByID.ClientID,
	}).Info("Getting client by ID")

	if clientByID.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Warn("Client ID is empty")
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
	log.WithFields(log.Fields{
		"clientID": clientByID.ClientID,
	}).Info("Disabling client by ID")
	if clientByID.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Warn("Client ID is empty")
		return Client{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientByID.ClientID)
	if err != nil {
		return client, err
	}
	client.DisableClient()
	client, err = c.clientRepostory.UpdateClient(client)
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Error("Error disabling client")
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
	log.WithFields(log.Fields{
		"clientID": clientByID.ClientID,
	}).Info("Enabling client by ID")
	if clientByID.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Warn("Client ID is empty")
		return Client{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientByID.ClientID)
	if err != nil {
		return client, err
	}
	client.EnableClient()
	client, err = c.clientRepostory.UpdateClient(client)
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Error("Error enabling client")
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
	log.WithFields(log.Fields{
		"clientID": clientAuthentication.ClientID,
	}).Info("Authenticating client")

	if clientAuthentication.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": clientAuthentication.ClientID,
		}).Warn("Client ID is empty")
		return Client{}, ErrClientIDEmpty
	}
	if clientAuthentication.ClientSecret == "" {
		log.WithFields(log.Fields{
			"clientID": clientAuthentication.ClientID,
		}).Warn("Client secret is empty")
		return Client{}, ErrClientSecretEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientAuthentication.ClientID)
	if err != nil {
		return client, err
	}
	if !client.IsEnabled() {
		log.WithFields(log.Fields{
			"clientID": clientAuthentication.ClientID,
		}).Warn("Client is disabled")
		return client, ErrClientDisabled
	}
	err = bcrypt.CompareHashAndPassword(util.FromStringToByteArray(client.GetSecret()), util.FromStringToByteArray(clientAuthentication.ClientSecret))
	if err != nil {
		return client, err
	}
	return client, nil
}
