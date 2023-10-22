package client

import (
	util "github.com/cirrostratus-cloud/oauth2/util"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

type CreateClientService struct {
	secretLenght           int
	clientRepostory        ClientRepository
	clientCreatedPublisher ClientCreatedPublisher
}

func (c CreateClientService) NewClient(createClient CreateClient) (CreateClientResult, error) {
	log.WithFields(log.Fields{
		"redirectURIs": createClient.RedirectURIs,
	}).Info("Creating new client")

	randomSecret := util.NewRandonSecret(c.secretLenght, c.isSecretUnique)

	secret, err := bcrypt.GenerateFromPassword(util.FromStringToByteArray(randomSecret), bcrypt.DefaultCost)
	if err != nil {
		return CreateClientResult{}, err
	}
	client, err := NewClient(uuid.NewString(), util.FromByteArrayToString(secret), createClient.RedirectURIs)
	if err != nil {
		return CreateClientResult{}, err
	}
	client, err = c.clientRepostory.CreateClient(client)
	if err != nil {
		return CreateClientResult{}, err
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
		return CreateClientResult{}, err
	}
	return CreateClientResult{
		ClientID:     client.GetID(),
		ClientSecret: randomSecret,
		RedirectURIs: client.GetRedirectURIs(),
		Enabled:      client.IsEnabled(),
	}, nil
}

func NewCreateClientService(secretLenght int, clientRepostory ClientRepository, clientCreatedPublisher ClientCreatedPublisher) CreateClientUseCase {
	return CreateClientService{
		secretLenght:           secretLenght,
		clientRepostory:        clientRepostory,
		clientCreatedPublisher: clientCreatedPublisher,
	}
}

func (c CreateClientService) isSecretUnique(secret string) (bool, error) {
	client, err := c.clientRepostory.FindClientByHashedSecret(secret)
	if err != nil {
		return false, err
	}
	if client.GetID() != "" {
		log.Warn("Client secret already exists")
		return false, nil
	}
	return true, nil
}

type GetClientService struct {
	clientRepostory ClientRepository
}

func NewGetClientService(clientRepostory ClientRepository) GetClientUseCase {
	return GetClientService{clientRepostory}
}

func (c GetClientService) GetClientByID(clientByID ClientByID) (GetClientResult, error) {
	log.WithFields(log.Fields{
		"clientID": clientByID.ClientID,
	}).Info("Getting client by ID")

	if clientByID.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Warn("Client ID is empty")
		return GetClientResult{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientByID.ClientID)
	if err != nil {
		return GetClientResult{}, err
	}
	return GetClientResult{
		ClientID:     client.GetID(),
		Enabled:      client.IsEnabled(),
		RedirectURIs: client.GetRedirectURIs(),
	}, nil
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

func (c DisableClientService) DisableClientByID(clientByID ClientByID) (DisabledClientResult, error) {
	log.WithFields(log.Fields{
		"clientID": clientByID.ClientID,
	}).Info("Disabling client by ID")
	if clientByID.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Warn("Client ID is empty")
		return DisabledClientResult{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientByID.ClientID)
	if err != nil {
		return DisabledClientResult{}, err
	}
	client.DisableClient()
	client, err = c.clientRepostory.UpdateClient(client)
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Error("Error disabling client")
		client.EnableClient()
		client, err = c.clientRepostory.UpdateClient(client)
		return DisabledClientResult{}, err
	}
	err = c.clientDisabledPublisher.ClientDisabled(ClientDisabledEvent{
		ClientID: client.GetID(),
	})
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Error("Error publishing client disabled event")
		client.EnableClient()
		client, err = c.clientRepostory.UpdateClient(client)
		return DisabledClientResult{}, err
	}
	return DisabledClientResult{
		ClientID: client.GetID(),
		Enabled:  client.IsEnabled(),
	}, nil
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

func (c EnableClientService) EnableClientByID(clientByID ClientByID) (EnabledClientResult, error) {
	log.WithFields(log.Fields{
		"clientID": clientByID.ClientID,
	}).Info("Enabling client by ID")
	if clientByID.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Warn("Client ID is empty")
		return EnabledClientResult{}, ErrClientIDEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientByID.ClientID)
	if err != nil {
		return EnabledClientResult{}, err
	}
	client.EnableClient()
	client, err = c.clientRepostory.UpdateClient(client)
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Error("Error enabling client")
		client.DisableClient()
		client, err = c.clientRepostory.UpdateClient(client)
		return EnabledClientResult{}, err
	}
	err = c.clientEnablePublisher.ClientEnabled(ClientEnabledEvent{
		ClientID: client.GetID(),
	})
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": clientByID.ClientID,
		}).Error("Error publishing client enabled event")
		client.DisableClient()
		client, err = c.clientRepostory.UpdateClient(client)
		return EnabledClientResult{}, err
	}
	return EnabledClientResult{
		ClientID: client.GetID(),
		Enabled:  client.IsEnabled(),
	}, nil
}

type AuthenticateClientService struct {
	clientRepostory ClientRepository
}

func NewAuthenticateClientService(clientRepostory ClientRepository) AuthenticateClientUseCase {
	return AuthenticateClientService{clientRepostory}
}

func (c AuthenticateClientService) AuthenticateClient(clientAuthentication ClientAuthentication) (AuthenticatedClientResult, error) {
	log.WithFields(log.Fields{
		"clientID": clientAuthentication.ClientID,
	}).Info("Authenticating client")

	if clientAuthentication.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": clientAuthentication.ClientID,
		}).Warn("Client ID is empty")
		return AuthenticatedClientResult{}, ErrClientIDEmpty
	}
	if clientAuthentication.ClientSecret == "" {
		log.WithFields(log.Fields{
			"clientID": clientAuthentication.ClientID,
		}).Warn("Client secret is empty")
		return AuthenticatedClientResult{}, ErrClientSecretEmpty
	}
	client, err := c.clientRepostory.FindClientByID(clientAuthentication.ClientID)
	if err != nil {
		return AuthenticatedClientResult{}, err
	}
	if !client.IsEnabled() {
		log.WithFields(log.Fields{
			"clientID": clientAuthentication.ClientID,
		}).Warn("Client is disabled")
		return AuthenticatedClientResult{}, ErrClientDisabled
	}
	err = bcrypt.CompareHashAndPassword(util.FromStringToByteArray(client.GetSecret()), util.FromStringToByteArray(clientAuthentication.ClientSecret))
	if err != nil {
		return AuthenticatedClientResult{}, err
	}
	return AuthenticatedClientResult{
		ClientID: client.GetID(),
	}, nil
}

type UpdateRedirectURIsService struct {
	clientRepostory                    ClientRepository
	clientRedirectURIsUpdatedPublisher ClientRedirectURIsUpdatedPublisher
}

func NewUpdateRedirectURIsService(clientRepostory ClientRepository, clientRedirectURIsUpdatedPublisher ClientRedirectURIsUpdatedPublisher) UpdateRedirectURIsUseCase {
	return UpdateRedirectURIsService{clientRepostory, clientRedirectURIsUpdatedPublisher}
}

func (u UpdateRedirectURIsService) UpdateRedirectURIs(updateRedirectURIs UpdateRedirectURIs) (UpdateRedirectURIsResult, error) {
	log.WithFields(log.Fields{
		"clientID":     updateRedirectURIs.ClientID,
		"redirectURIs": updateRedirectURIs.RedirectURIs,
	}).Info("Updating client redirect URIs")

	if updateRedirectURIs.ClientID == "" {
		log.WithFields(log.Fields{
			"clientID": updateRedirectURIs.ClientID,
		}).Warn("Client ID is empty")
		return UpdateRedirectURIsResult{}, ErrClientIDEmpty
	}
	client, err := u.clientRepostory.FindClientByID(updateRedirectURIs.ClientID)
	if err != nil {
		return UpdateRedirectURIsResult{}, err
	}
	client.UpdateRedirectURIs(updateRedirectURIs.RedirectURIs)
	client, err = u.clientRepostory.UpdateClient(client)
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": updateRedirectURIs.ClientID,
		}).Error("Error updating client redirect URIs")
		return UpdateRedirectURIsResult{}, err
	}
	err = u.clientRedirectURIsUpdatedPublisher.ClientRedirectURIsUpdated(ClientRedirectURIsUpdatedEvent{
		ClientID:     client.GetID(),
		RedirectURIs: client.GetRedirectURIs(),
	})
	if err != nil {
		log.WithFields(log.Fields{
			"clientID": updateRedirectURIs.ClientID,
		}).Error("Error publishing client redirect URIs updated event")
		return UpdateRedirectURIsResult{}, err
	}
	return UpdateRedirectURIsResult{
		ClientID:     client.GetID(),
		RedirectURIs: client.GetRedirectURIs(),
	}, nil
}
