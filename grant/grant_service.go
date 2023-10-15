package grant

import (
	"errors"

	"github.com/cirrostratus-cloud/oauth2/authorization"
	"github.com/cirrostratus-cloud/oauth2/client"
	"github.com/cirrostratus-cloud/oauth2/util"
)

var ErrRedirectURINotFound = errors.New("redirect URI not found")

type AuthorizationCodeUserAgentGrantService struct {
	codeLenght                     int
	getClientService               client.GetClientUseCase
	createAuthorizationCodeUseCase authorization.CreateAuthorizationCodeUseCase
}

func NewAuthorizationCodeUserAgentGrantService(codeLenght int, getClientService client.GetClientService) AuthorizationUserAgentUseCase {
	return AuthorizationCodeUserAgentGrantService{codeLenght: codeLenght, getClientService: getClientService}
}

func (a AuthorizationCodeUserAgentGrantService) AuthorizeWithUserAgentParams(userAgentGrant AuthorizationCodeUserAgentRequest) (AuthorizationCodeUserAgentResponse, error) {
	// FIXME: Add logs
	if userAgentGrant.ResponseType != string(ResponseTypeCode) {
		return AuthorizationCodeUserAgentResponse{}, errors.New("invalid response type")
	}
	// FIXME: Validate redirect URI
	// FIXME: Validate client credentials
	client, err := a.getClientService.GetClientByID(client.ClientByID{
		ClientID: userAgentGrant.ClientID,
	})
	if err != nil {
		return AuthorizationCodeUserAgentResponse{}, err
	}
	if !client.ExistsRedirectURI(userAgentGrant.RedirectURI) {
		return AuthorizationCodeUserAgentResponse{}, ErrRedirectURINotFound
	}
	grantCode := AuthorizationCodeUserAgentResponse{
		Code:        util.NewRandomCode(a.codeLenght),
		State:       userAgentGrant.State,
		ErrorCode:   ErrorCodeEmpty,
		RedirectURI: userAgentGrant.RedirectURI,
	}
	_, err = a.createAuthorizationCodeUseCase.NewAuthorizationCode(grantCode.Code, userAgentGrant.RedirectURI, userAgentGrant.ClientID)
	if err != nil {
		return AuthorizationCodeUserAgentResponse{}, err
	}
	return grantCode, nil
}

type AuthorizationCodeService struct {
	getClientService                   client.GetClientUseCase
	getAuthorizationCodeUseService     authorization.GetAuthorizationCodeUseCase
	accessTokenExpirationTimeInSeconds int
}

func NewAuthorizationCodeService(getClientService client.GetClientUseCase, getAuthorizationCodeUseService authorization.GetAuthorizationCodeUseCase) AuthorizationCodeGrantUseCase {
	return AuthorizationCodeService{getClientService: getClientService, getAuthorizationCodeUseService: getAuthorizationCodeUseService}
}

func (a AuthorizationCodeService) AuthorizeWithCode(authorizationCode AuthorizationCodeRequest) (AuthorizationCodeResponse, error) {
	// FIXME: Add logs
	// FIXME: Validate client credentials
	// FIXME: Validate scopes
	if authorizationCode.GrantType != string(GrantTypeAuthorizationCodeRequest) {
		return AuthorizationCodeResponse{}, errors.New("invalid grant type")
	}
	codeSession, err := a.getAuthorizationCodeUseService.GetAuthorizationCodeByCode(authorizationCode.Code)
	if err != nil {
		return AuthorizationCodeResponse{}, err
	}
	if codeSession.IsExpired() {
		return AuthorizationCodeResponse{}, errors.New("authorization session code is expired")
	}
	// FIXME: Create JWT token using AccessToken and RefreshToken entities
	grantToken := AuthorizationCodeResponse{
		AccessToken:  util.NewRandomCode(32),
		TokenType:    string(TokenTypeBearer),
		ExpiresIn:    a.accessTokenExpirationTimeInSeconds,
		RefreshToken: util.NewRandomCode(32),
	}
	return grantToken, nil
}

type ImplicitGrantService struct {
	getClientService                   client.GetClientUseCase
	accessTokenExpirationTimeInSeconds int
}

func NewImplicitGrantService(getClientService client.GetClientUseCase, accessTokenExpirationTimeInSeconds int) ImplicitGrantUseCase {
	return ImplicitGrantService{getClientService: getClientService, accessTokenExpirationTimeInSeconds: accessTokenExpirationTimeInSeconds}
}

func (i ImplicitGrantService) AuthorizeImplicitWithUserAgentParams(implicit ImplicitUserAgentRequest) (ImplicitUserAgentResponse, error) {
	// FIXME: Add logs
	if implicit.ResponseType != string(ResponseTypeToken) {
		return ImplicitUserAgentResponse{}, errors.New("invalid response type")
	}
	// FIXME: Validate scopes
	client, err := i.getClientService.GetClientByID(client.ClientByID{
		ClientID: implicit.ClientID,
	})
	if err != nil {
		return ImplicitUserAgentResponse{}, err
	}
	// FIXME: Validate redirect URI

	if !client.ExistsRedirectURI(implicit.RedirectURI) {
		return ImplicitUserAgentResponse{}, ErrRedirectURINotFound
	}

	if err != nil {
		return ImplicitUserAgentResponse{}, err
	}
	if implicit.ResponseType != "token" {
		return ImplicitUserAgentResponse{}, errors.New("invalid response type")
	}
	// FIXME: Create JWT token using AccessToken and RefreshToken entities
	return ImplicitUserAgentResponse{
		AccessToken: util.NewRandomCode(32),
		TokenType:   string(TokenTypeBearer),
		ExpiresIn:   i.accessTokenExpirationTimeInSeconds,
		RedirectURI: implicit.RedirectURI,
	}, nil
}

type PasswordCredentialsGrantService struct {
	getClientService                   client.GetClientUseCase
	accessTokenExpirationTimeInSeconds int
}

func NewPasswordCredentialsGrantService(getClientService client.GetClientUseCase, accessTokenExpirationTimeInSeconds int) PasswordCredentialsGrantUseCase {
	return PasswordCredentialsGrantService{getClientService: getClientService, accessTokenExpirationTimeInSeconds: accessTokenExpirationTimeInSeconds}
}

func (p PasswordCredentialsGrantService) AuthorizeWithPasswordCredentials(resourceOwnerPasswordCredentials ResourceOwnerPasswordCredentialsRequest) (ResourceOwnerPasswordCredentialsResponse, error) {
	// FIXME: Add logs
	// FIXME: Validate client credentials
	// FIXME: Validate user credentials
	if resourceOwnerPasswordCredentials.GrantType != string(GrantTypePassword) {
		return ResourceOwnerPasswordCredentialsResponse{}, errors.New("invalid grant type")
	}
	// FIXME: Validate scopes
	// FIXME: Generate tokens
	return ResourceOwnerPasswordCredentialsResponse{
		AccessToken:  util.NewRandomCode(32),
		TokenType:    string(TokenTypeBearer),
		ExpiresIn:    p.accessTokenExpirationTimeInSeconds,
		RefreshToken: util.NewRandomCode(32),
		Scope:        resourceOwnerPasswordCredentials.Scope,
	}, nil
}

type ClientCredentialsGrantService struct {
	getClientService                   client.GetClientUseCase
	accessTokenExpirationTimeInSeconds int
}

func NewClientCredentialsGrantService(getClientService client.GetClientUseCase, accessTokenExpirationTimeInSeconds int) ClientCredentialsGrantUseCase {
	return ClientCredentialsGrantService{getClientService: getClientService, accessTokenExpirationTimeInSeconds: accessTokenExpirationTimeInSeconds}
}

func (c ClientCredentialsGrantService) AuthorizeWithClientCredentials(clientCredentials ClientCredentialsRequest) (ClientCredentialsResponse, error) {
	// FIXME: Add logs
	// FIXME: Validate client credentials
	if clientCredentials.GrantType != string(GrantTypeClientCredentialsRequest) {
		return ClientCredentialsResponse{}, errors.New("invalid grant type")
	}
	// FIXME: Validate scopes
	// FIXME: Generate tokens
	return ClientCredentialsResponse{
		AccessToken:  util.NewRandomCode(32),
		TokenType:    string(TokenTypeBearer),
		ExpiresIn:    c.accessTokenExpirationTimeInSeconds,
		RefreshToken: util.NewRandomCode(32),
		Scope:        clientCredentials.Scope,
	}, nil
}
