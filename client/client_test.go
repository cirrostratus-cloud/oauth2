package client_test

import (
	"errors"
	"testing"

	"github.com/cirrostratus-cloud/oauth2/client"
	mevent "github.com/cirrostratus-cloud/oauth2/mocks/github.com/cirrostratus-cloud/common/event"
	mclient "github.com/cirrostratus-cloud/oauth2/mocks/github.com/cirrostratus-cloud/oauth2/client"
	"github.com/cirrostratus-cloud/oauth2/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateClientOk(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientRepostory.
		On("CreateClient", mock.AnythingOfType("client.Client")).
		Return(func(c client.Client) (client.Client, error) {
			return c, nil
		}).
		Times(1)
	clientRepostory.
		EXPECT().
		FindClientByHashedSecret(mock.AnythingOfType("string")).
		Return(client.Client{}, nil).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Publish(client.ClientCreatedEventName, mock.Anything).
		Return(nil).
		Times(1)
	clientCreatedPublisher := client.NewClientCreatedPublisher(eventBus)
	createClientService := client.NewCreateClientService(10, clientRepostory, clientCreatedPublisher)
	createdClient, err := createClientService.NewClient(client.CreateClient{
		RedirectURIs: []string{"http://localhost:8080"},
	})
	assert.NoError(err)
	assert.NotEmpty(createdClient.GetID())
	assert.NotEmpty(createdClient.GetSecret())
	assert.NotNil(createdClient.GetRedirectURIs())
	assert.True(createdClient.IsEnabled())
}

func TestCreateClientInvalidURI(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientRepostory.
		EXPECT().
		FindClientByHashedSecret(mock.AnythingOfType("string")).
		Return(client.Client{}, nil).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	clientCreatedPublisher := client.NewClientCreatedPublisher(eventBus)
	createClientService := client.NewCreateClientService(10, clientRepostory, clientCreatedPublisher)
	_, err := createClientService.NewClient(client.CreateClient{
		RedirectURIs: []string{"http://localhost:8080", "cirrostratus.cloud.com/callback"},
	})
	assert.Error(err)
	assert.Equal(util.ErrInvalidURI, err)
}

func TestCreateClientNoRedirectURIs(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientRepostory.
		EXPECT().
		FindClientByHashedSecret(mock.AnythingOfType("string")).
		Return(client.Client{}, nil).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	clientCreatedPublisher := client.NewClientCreatedPublisher(eventBus)
	createClientService := client.NewCreateClientService(10, clientRepostory, clientCreatedPublisher)
	_, err := createClientService.NewClient(client.CreateClient{})
	assert.Error(err)
	assert.Equal(client.ErrRedirectURISEmpty, err)
}

func TestCreateClientDisableOk(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	c, err := client.NewClient("clientID", "clientSecret", []string{"http://localhost:8080"})
	assert.NoError(err)
	clientRepostory.
		EXPECT().
		FindClientByID("clientID").
		Return(c, nil).
		Times(1)
	clientRepostory.
		On("UpdateClient", mock.AnythingOfType("client.Client")).
		Return(func(c client.Client) (client.Client, error) {
			return c, nil
		}).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Publish(client.ClientDisabledEventName, client.ClientDisabledEvent{
			ClientID: "clientID",
		}).
		Return(nil).
		Times(1)
	clientDisabledPublisher := client.NewClientDisabledPublisher(eventBus)
	createClientService := client.NewDisableClientService(clientRepostory, clientDisabledPublisher)
	createdClient, err := createClientService.DisableClientByID(client.ClientByID{
		ClientID: "clientID",
	})
	assert.NoError(err)
	assert.False(createdClient.IsEnabled())
}

func TestCreateClientDisableNotFound(t *testing.T) {
	clientNotFound := errors.New("client not found")
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientRepostory.
		EXPECT().
		FindClientByID("clientID").
		Return(client.Client{}, clientNotFound).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	clientDisabledPublisher := client.NewClientDisabledPublisher(eventBus)
	createClientService := client.NewDisableClientService(clientRepostory, clientDisabledPublisher)
	_, err := createClientService.DisableClientByID(client.ClientByID{
		ClientID: "clientID",
	})
	assert.Error(err)
	assert.Equal(clientNotFound, err)
}

func TestCreateClientDisableEmptyID(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	eventBus := mevent.NewMockEventBus(t)
	clientDisabledPublisher := client.NewClientDisabledPublisher(eventBus)
	createClientService := client.NewDisableClientService(clientRepostory, clientDisabledPublisher)
	_, err := createClientService.DisableClientByID(client.ClientByID{
		ClientID: "",
	})
	assert.Error(err)
	assert.Equal(client.ErrClientIDEmpty, err)
}

func TestCreateClientEnableOk(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	c, err := client.NewClient("clientID", "clientSecret", []string{"http://localhost:8080"})
	assert.NoError(err)
	c.DisableClient()
	clientRepostory.
		EXPECT().
		FindClientByID("clientID").
		Return(c, nil).
		Times(1)
	clientRepostory.
		On("UpdateClient", mock.AnythingOfType("client.Client")).
		Return(func(c client.Client) (client.Client, error) {
			return c, nil
		}).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Publish(client.ClientEnabledEventName, client.ClientEnabledEvent{
			ClientID: "clientID",
		}).
		Return(nil).
		Times(1)
	clientEnabledPublisher := client.NewClientEnabledPublisher(eventBus)
	createClientService := client.NewEnableClientService(clientRepostory, clientEnabledPublisher)
	createdClient, err := createClientService.EnableClientByID(client.ClientByID{
		ClientID: "clientID",
	})
	assert.NoError(err)
	assert.True(createdClient.IsEnabled())
}

func TestCreateClientEnableNotFound(t *testing.T) {
	clientNotFound := errors.New("client not found")
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientRepostory.
		EXPECT().
		FindClientByID("clientID").
		Return(client.Client{}, clientNotFound).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	clientEnabledPublisher := client.NewClientEnabledPublisher(eventBus)
	createClientService := client.NewEnableClientService(clientRepostory, clientEnabledPublisher)
	_, err := createClientService.EnableClientByID(client.ClientByID{
		ClientID: "clientID",
	})
	assert.Error(err)
	assert.Equal(clientNotFound, err)
}

func TestCreateClientEnableEmptyID(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	eventBus := mevent.NewMockEventBus(t)
	clientEnabledPublisher := client.NewClientEnabledPublisher(eventBus)
	createClientService := client.NewEnableClientService(clientRepostory, clientEnabledPublisher)
	_, err := createClientService.EnableClientByID(client.ClientByID{
		ClientID: "",
	})
	assert.Error(err)
	assert.Equal(client.ErrClientIDEmpty, err)
}

func TestAuthenticateClientOk(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientSecret := "clientSecret"
	clientID := "clientID"
	hashedSecret, err := bcrypt.GenerateFromPassword(util.FromStringToByteArray(clientSecret), bcrypt.DefaultCost)
	assert.NoError(err)
	c, err := client.NewClient(clientID, util.FromByteArrayToString(hashedSecret), []string{"http://localhost:8080"})
	assert.NoError(err)
	clientRepostory.
		EXPECT().
		FindClientByID(clientID).
		Return(c, nil).
		Times(1)
	authenticateClientService := client.NewAuthenticateClientService(clientRepostory)
	_, err = authenticateClientService.AuthenticateClient(client.ClientAuthentication{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	assert.NoError(err)
}

func TestAuthenticateClientEmptyID(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	authenticateClientService := client.NewAuthenticateClientService(clientRepostory)
	_, err := authenticateClientService.AuthenticateClient(client.ClientAuthentication{
		ClientID:     "",
		ClientSecret: "clientSecret",
	})
	assert.Error(err)
	assert.Equal(client.ErrClientIDEmpty, err)
}

func TestAuthenticateClientEmptySecret(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	authenticateClientService := client.NewAuthenticateClientService(clientRepostory)
	_, err := authenticateClientService.AuthenticateClient(client.ClientAuthentication{
		ClientID:     "clientID",
		ClientSecret: "",
	})
	assert.Error(err)
	assert.Equal(client.ErrClientSecretEmpty, err)
}

func TestAuthenticateClientNotFound(t *testing.T) {
	clientNotFound := errors.New("client not found")
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientRepostory.
		EXPECT().
		FindClientByID("clientID").
		Return(client.Client{}, clientNotFound).
		Times(1)
	authenticateClientService := client.NewAuthenticateClientService(clientRepostory)
	_, err := authenticateClientService.AuthenticateClient(client.ClientAuthentication{
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
	})
	assert.Error(err)
	assert.Equal(clientNotFound, err)
}

func TestAuthenticateClientDisabled(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	c, err := client.NewClient("clientID", "clientSecret", []string{"http://localhost:8080"})
	assert.NoError(err)
	c.DisableClient()
	clientRepostory.
		EXPECT().
		FindClientByID("clientID").
		Return(c, nil).
		Times(1)
	authenticateClientService := client.NewAuthenticateClientService(clientRepostory)
	_, err = authenticateClientService.AuthenticateClient(client.ClientAuthentication{
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
	})
	assert.Error(err)
	assert.Equal(client.ErrClientDisabled, err)
}

func TestAuthenticateClientInvalidSecret(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientSecret := "clientSecret"
	clientID := "clientID"
	hashedSecret, err := bcrypt.GenerateFromPassword(util.FromStringToByteArray(clientSecret), bcrypt.DefaultCost)
	assert.NoError(err)
	c, err := client.NewClient(clientID, util.FromByteArrayToString(hashedSecret), []string{"http://localhost:8080"})
	assert.NoError(err)
	clientRepostory.
		EXPECT().
		FindClientByID(clientID).
		Return(c, nil).
		Times(1)
	authenticateClientService := client.NewAuthenticateClientService(clientRepostory)
	_, err = authenticateClientService.AuthenticateClient(client.ClientAuthentication{
		ClientID:     clientID,
		ClientSecret: "invalidSecret",
	})
	assert.Error(err)
}

func TestGetClientByIDOk(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientID := "clientID"
	c, err := client.NewClient(clientID, "clientSecret", []string{"http://localhost:8080"})
	assert.NoError(err)
	clientRepostory.
		EXPECT().
		FindClientByID(clientID).
		Return(c, nil).
		Times(1)
	getClientService := client.NewGetClientService(clientRepostory)
	_, err = getClientService.GetClientByID(client.ClientByID{
		ClientID: clientID,
	})
	assert.NoError(err)
}

func TestGetClientByIDEmptyID(t *testing.T) {
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	getClientService := client.NewGetClientService(clientRepostory)
	_, err := getClientService.GetClientByID(client.ClientByID{
		ClientID: "",
	})
	assert.Error(err)
	assert.Equal(client.ErrClientIDEmpty, err)
}

func TestGetClientByIDNotFound(t *testing.T) {
	clientNotFound := errors.New("client not found")
	assert := assert.New(t)
	clientRepostory := mclient.NewMockClientRepository(t)
	clientRepostory.
		EXPECT().
		FindClientByID("clientID").
		Return(client.Client{}, clientNotFound).
		Times(1)
	getClientService := client.NewGetClientService(clientRepostory)
	_, err := getClientService.GetClientByID(client.ClientByID{
		ClientID: "clientID",
	})
	assert.Error(err)
	assert.Equal(clientNotFound, err)
}
