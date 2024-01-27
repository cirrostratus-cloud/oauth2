package grant

import (
	"errors"
	"time"

	"github.com/cirrostratus-cloud/common/ulid"
	"github.com/cirrostratus-cloud/oauth2/authorization"
	"github.com/cirrostratus-cloud/oauth2/client"
	"github.com/dgrijalva/jwt-go"
	log "github.com/sirupsen/logrus"
)

var ErrRedirectURINotFound = errors.New("redirect URI not found")
var ErrInvalidGrantType = errors.New("invalid grant type")
var ErrSessionCodeExpired = errors.New("session code expired")
var ErrInvalidResponseType = errors.New("invalid response type")

type tokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
}

// TODO: Cambiar esto por un caso de uso
func getTokens(createAccessTokenUseCase CreateAccessTokenUseCase, createRefreshTokenUseCase CreateRefreshTokenUseCase, clientID string, privateKey []byte) (tokens, error) {
	log.WithFields(log.Fields{
		"client_id": clientID,
	}).Info("Get tokens")
	accessToken, err := createAccessTokenUseCase.NewAccessToken(clientID)
	if err != nil {
		return tokens{}, err
	}
	accessTokenString, err := getAccessTokenString(accessToken, privateKey)
	if err != nil {
		return tokens{}, err
	}
	refreshToken, err := createRefreshTokenUseCase.NewRefreshToken(clientID)
	if err != nil {
		return tokens{}, err
	}
	refreshTokenString, err := getRefreshTokenString(refreshToken, privateKey)
	if err != nil {
		return tokens{}, err
	}
	return tokens{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresIn:    accessToken.GetExpirationTimeInSeconds(),
	}, nil
}

type AuthorizationCodeUserAgentGrantService struct {
	getClientService               client.GetClientUseCase
	createAuthorizationCodeUseCase authorization.CreateAuthorizationCodeUseCase
}

func NewAuthorizationCodeUserAgentGrantService(codeLenght int, getClientService client.GetClientService) AuthorizationUserAgentUseCase {
	return AuthorizationCodeUserAgentGrantService{getClientService: getClientService}
}

func (a AuthorizationCodeUserAgentGrantService) AuthorizeWithUserAgentParams(userAgentGrant AuthorizationCodeUserAgentRequest) (AuthorizationCodeUserAgentResponse, error) {
	log.WithFields(log.Fields{
		"client_id":     userAgentGrant.ClientID,
		"redirect_uri":  userAgentGrant.RedirectURI,
		"response_type": userAgentGrant.ResponseType,
		"scope":         userAgentGrant.Scope,
		"state":         userAgentGrant.State,
	}).Info("Authorize with user agent")
	if userAgentGrant.ResponseType != string(ResponseTypeCode) {
		return AuthorizationCodeUserAgentResponse{}, errors.New("invalid response type")
	}
	client, err := a.getClientService.GetClientByID(client.ClientByID{
		ClientID: userAgentGrant.ClientID,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"client_id": userAgentGrant.ClientID,
		}).Error("Get client by ID error")
		return AuthorizationCodeUserAgentResponse{}, err
	}
	if !existsRedirectURI(userAgentGrant.RedirectURI, client.RedirectURIs) {
		log.WithFields(log.Fields{
			"client_id":    userAgentGrant.ClientID,
			"redirect_uri": userAgentGrant.RedirectURI,
		}).Error("Redirect URI not found")
		return AuthorizationCodeUserAgentResponse{}, ErrRedirectURINotFound
	}
	authorizationCode, err := a.createAuthorizationCodeUseCase.NewAuthorizationCode(authorization.AuthorizationCodeGrantRequest{
		ClientID:    userAgentGrant.ClientID,
		RedirectURI: userAgentGrant.RedirectURI,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"client_id":    userAgentGrant.ClientID,
			"redirect_uri": userAgentGrant.RedirectURI,
		}).Error("Create authorization code error")
		return AuthorizationCodeUserAgentResponse{}, err
	}
	grantCode := AuthorizationCodeUserAgentResponse{
		Code:        authorizationCode.Code,
		State:       userAgentGrant.State,
		ErrorCode:   ErrorCodeEmpty,
		RedirectURI: userAgentGrant.RedirectURI,
	}
	return grantCode, nil
}

type AuthorizationCodeService struct {
	getClientService               client.GetClientUseCase
	getAuthorizationCodeUseService authorization.GetAuthorizationCodeUseCase
	createAccessTokenService       CreateAccessTokenUseCase
	createRefreshTokenService      CreateRefreshTokenUseCase
	privateKey                     []byte
}

func NewAuthorizationCodeService(getClientService client.GetClientUseCase, getAuthorizationCodeUseService authorization.GetAuthorizationCodeUseCase, createAccessTokenUserCase CreateAccessTokenUseCase, createResfreshTokenUseCase CreateRefreshTokenUseCase, privateKey []byte) AuthorizationCodeGrantUseCase {
	return AuthorizationCodeService{getClientService: getClientService, getAuthorizationCodeUseService: getAuthorizationCodeUseService, createAccessTokenService: createAccessTokenUserCase, createRefreshTokenService: createResfreshTokenUseCase, privateKey: privateKey}
}

func getAccessTokenString(accessToken AccessToken, privateKey []byte) (string, error) {
	claims := jwt.MapClaims{
		"iss":             accessToken.GetIssuer(),
		"sub":             accessToken.GetSubject(),
		"aud":             accessToken.GetAudience(),
		"exp":             accessToken.GetExpirationTimeInSeconds(),
		"additional_data": accessToken.GetAdditionalData(),
	}
	accessTokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessTokenString, err := accessTokenClaims.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return accessTokenString, nil
}

func getRefreshTokenString(refreshToken RefreshToken, privateKey []byte) (string, error) {
	claims := jwt.MapClaims{
		"iss": refreshToken.GetIssuer(),
		"sub": refreshToken.GetSubject(),
		"aud": refreshToken.GetAudience(),
		"exp": refreshToken.GetExpirationTimeInSeconds(),
	}
	refreshTokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refreshTokenString, err := refreshTokenClaims.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return refreshTokenString, nil
}

func (a AuthorizationCodeService) AuthorizeWithCode(authorizationCode AuthorizationCodeRequest) (AuthorizationCodeResponse, error) {
	log.WithFields(log.Fields{
		"client_id":    authorizationCode.ClientID,
		"grant_type":   authorizationCode.GrantType,
		"redirect_uri": authorizationCode.RedirectURI,
	}).Info("Authorize with code")
	if authorizationCode.GrantType != string(GrantTypeAuthorizationCodeRequest) {
		return AuthorizationCodeResponse{}, ErrInvalidGrantType
	}
	_, err := a.getClientService.GetClientByID(client.ClientByID{
		ClientID: authorizationCode.ClientID,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"client_id":    authorizationCode.ClientID,
			"grant_type":   authorizationCode.GrantType,
			"redirect_uri": authorizationCode.RedirectURI,
		}).
			WithError(err).
			Error("Get client by ID error")
		return AuthorizationCodeResponse{}, err
	}
	// TODO: Validate scopes
	_, err = a.getAuthorizationCodeUseService.GetAuthorizationCodeByCode(authorization.AuthorizationCodeGrantRequest{
		ClientID:    authorizationCode.ClientID,
		Code:        authorizationCode.Code,
		RedirectURI: authorizationCode.RedirectURI,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"client_id":    authorizationCode.ClientID,
			"redirect_uri": authorizationCode.RedirectURI,
		}).
			WithError(err).
			Error("Get authorization code by code error")
		return AuthorizationCodeResponse{}, err
	}
	tokens, err := getTokens(a.createAccessTokenService, a.createRefreshTokenService, authorizationCode.ClientID, a.privateKey)
	if err != nil {
		log.WithFields(log.Fields{
			"client_id":    authorizationCode.ClientID,
			"redirect_uri": authorizationCode.RedirectURI,
		}).
			WithError(err).
			Error("Get tokens error")
		return AuthorizationCodeResponse{}, err
	}
	grantToken := AuthorizationCodeResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    string(TokenTypeBearer),
		ExpiresIn:    tokens.ExpiresIn,
		RefreshToken: tokens.RefreshToken,
	}
	return grantToken, nil
}

type ImplicitGrantService struct {
	getClientService         client.GetClientUseCase
	createAccessTokenUseCase CreateAccessTokenUseCase
	privateKey               []byte
}

func NewImplicitGrantService(getClientService client.GetClientUseCase, createAccessTokenUseCase CreateAccessTokenService, privateKey []byte) ImplicitGrantUseCase {
	return ImplicitGrantService{
		getClientService:         getClientService,
		createAccessTokenUseCase: createAccessTokenUseCase,
		privateKey:               privateKey,
	}
}

func (i ImplicitGrantService) AuthorizeImplicitWithUserAgentParams(implicit ImplicitUserAgentRequest) (ImplicitUserAgentResponse, error) {
	log.WithFields(log.Fields{
		"client_id":     implicit.ClientID,
		"redirect_uri":  implicit.RedirectURI,
		"response_type": implicit.ResponseType,
		"scope":         implicit.Scope,
	}).Info("Authorize implicit with user agent")
	if implicit.ResponseType != string(ResponseTypeToken) {
		return ImplicitUserAgentResponse{}, ErrInvalidResponseType
	}
	// TODO: Validate scopes
	client, err := i.getClientService.GetClientByID(client.ClientByID{
		ClientID: implicit.ClientID,
	})

	if err != nil {
		return ImplicitUserAgentResponse{}, err
	}

	if !existsRedirectURI(implicit.RedirectURI, client.RedirectURIs) {
		return ImplicitUserAgentResponse{}, ErrRedirectURINotFound
	}

	if err != nil {
		return ImplicitUserAgentResponse{}, err
	}

	if implicit.ResponseType != string(ResponseTypeToken) {
		return ImplicitUserAgentResponse{}, errors.New("invalid response type")
	}
	accessToken, err := i.createAccessTokenUseCase.NewAccessToken(implicit.ClientID)
	if err != nil {
		log.WithFields(log.Fields{
			"client_id":    implicit.ClientID,
			"redirect_uri": implicit.RedirectURI,
		}).
			WithError(err).
			Error("Create access token error")
		return ImplicitUserAgentResponse{}, err
	}
	accessTokenString, err := getAccessTokenString(accessToken, i.privateKey)
	if err != nil {
		log.WithFields(log.Fields{
			"client_id":    implicit.ClientID,
			"redirect_uri": implicit.RedirectURI,
		}).
			WithError(err).
			Error("Create access token error")
		return ImplicitUserAgentResponse{}, err
	}
	return ImplicitUserAgentResponse{
		AccessToken: accessTokenString,
		TokenType:   string(TokenTypeBearer),
		ExpiresIn:   accessToken.GetExpirationTimeInSeconds(),
		RedirectURI: implicit.RedirectURI,
	}, nil
}

type PasswordCredentialsGrantService struct {
	getClientService                   client.GetClientUseCase
	accessTokenExpirationTimeInSeconds int
	authenticateClientUseCase          client.AuthenticateClientUseCase
	createAccessTokenUseCase           CreateAccessTokenUseCase
	createRefreshTokenUseCase          CreateRefreshTokenUseCase
	privateKey                         []byte
}

func NewPasswordCredentialsGrantService(getClientService client.GetClientUseCase, authenticateClientUseCase client.AuthenticateClientUseCase, accessTokenExpirationTimeInSeconds int, createAccessTokenUseCase CreateAccessTokenUseCase, privateKey []byte, createRefreshTokenUseCase CreateRefreshTokenUseCase) PasswordCredentialsGrantUseCase {
	return PasswordCredentialsGrantService{
		getClientService:                   getClientService,
		accessTokenExpirationTimeInSeconds: accessTokenExpirationTimeInSeconds,
		authenticateClientUseCase:          authenticateClientUseCase,
		createAccessTokenUseCase:           createAccessTokenUseCase,
		privateKey:                         privateKey,
		createRefreshTokenUseCase:          createRefreshTokenUseCase}
}

func (p PasswordCredentialsGrantService) AuthorizeWithPasswordCredentials(resourceOwnerPasswordCredentials ResourceOwnerPasswordCredentialsRequest) (ResourceOwnerPasswordCredentialsResponse, error) {
	log.WithFields(log.Fields{
		"client_id":  resourceOwnerPasswordCredentials.ClientID,
		"grant_type": resourceOwnerPasswordCredentials.GrantType,
		"username":   resourceOwnerPasswordCredentials.Username,
		"scope":      resourceOwnerPasswordCredentials.Scope,
	}).Info("Authorize with password credentials")

	_, err := p.authenticateClientUseCase.AuthenticateClient(client.ClientAuthentication{
		ClientID:     resourceOwnerPasswordCredentials.ClientID,
		ClientSecret: resourceOwnerPasswordCredentials.ClientSecret,
	})
	if err != nil {
		log.WithFields(log.Fields{
			"client_id":  resourceOwnerPasswordCredentials.ClientID,
			"grant_type": resourceOwnerPasswordCredentials.GrantType,
			"username":   resourceOwnerPasswordCredentials.Username,
			"scope":      resourceOwnerPasswordCredentials.Scope,
		}).
			WithError(err).
			Error("Get client by ID error")
		return ResourceOwnerPasswordCredentialsResponse{}, err
	}

	if resourceOwnerPasswordCredentials.GrantType != string(GrantTypePassword) {
		return ResourceOwnerPasswordCredentialsResponse{}, errors.New("invalid grant type")
	}
	// FIXME: Validate scopes
	tokens, err := getTokens(p.createAccessTokenUseCase, p.createRefreshTokenUseCase, resourceOwnerPasswordCredentials.ClientID, p.privateKey)
	if err != nil {
		log.WithFields(log.Fields{
			"client_id": resourceOwnerPasswordCredentials.ClientID,
		}).
			WithError(err).
			Error("Get tokens error")
		return ResourceOwnerPasswordCredentialsResponse{}, err
	}
	return ResourceOwnerPasswordCredentialsResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    string(TokenTypeBearer),
		ExpiresIn:    tokens.ExpiresIn,
		RefreshToken: tokens.AccessToken,
		Scope:        resourceOwnerPasswordCredentials.Scope,
	}, nil
}

type ClientCredentialsGrantService struct {
	authenticateClientUseCase client.AuthenticateClientUseCase
	createAccessTokenUseCase  CreateAccessTokenUseCase
	createRefreshTokenUseCase CreateRefreshTokenUseCase
	privateKey                []byte
}

func NewClientCredentialsGrantService(authenticateClientUseCase client.AuthenticateClientUseCase, createAccessTokenUseCase CreateAccessTokenUseCase, createRefreshTokenUseCase CreateRefreshTokenUseCase, privateKey []byte) ClientCredentialsGrantUseCase {
	return ClientCredentialsGrantService{
		authenticateClientUseCase: authenticateClientUseCase,
		createAccessTokenUseCase:  createAccessTokenUseCase,
		createRefreshTokenUseCase: createRefreshTokenUseCase,
		privateKey:                privateKey,
	}
}

func (c ClientCredentialsGrantService) AuthorizeWithClientCredentials(clientCredentials ClientCredentialsRequest) (ClientCredentialsResponse, error) {
	// FIXME: Add logs
	log.
		WithFields(
			log.Fields{
				"client_id":  clientCredentials.ClientID,
				"grant_type": clientCredentials.GrantType,
				"scope":      clientCredentials.Scope,
			},
		).
		Info("Authorize with client credentials")
	if clientCredentials.GrantType != string(GrantTypeClientCredentialsRequest) {
		return ClientCredentialsResponse{}, errors.New("invalid grant type")
	}
	_, err := c.authenticateClientUseCase.AuthenticateClient(client.ClientAuthentication{
		ClientID:     clientCredentials.ClientID,
		ClientSecret: clientCredentials.ClientSecret,
	})
	if err != nil {
		log.WithFields(
			log.Fields{
				"client_id":  clientCredentials.ClientID,
				"grant_type": clientCredentials.GrantType,
				"scope":      clientCredentials.Scope,
			},
		).
			WithError(err).
			Error("Authentication error")
		return ClientCredentialsResponse{}, err
	}

	// FIXME: Validate scopes
	tokens, err := getTokens(c.createAccessTokenUseCase, c.createRefreshTokenUseCase, clientCredentials.ClientID, c.privateKey)
	if err != nil {
		log.WithFields(
			log.Fields{
				"client_id": clientCredentials.ClientID,
			},
		).
			WithError(err).
			Error("Get tokens error")
		return ClientCredentialsResponse{}, err
	}
	return ClientCredentialsResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    string(TokenTypeBearer),
		ExpiresIn:    tokens.ExpiresIn,
		RefreshToken: tokens.RefreshToken,
		Scope:        clientCredentials.Scope,
	}, nil
}

func existsRedirectURI(redirectURI string, redirectURIs []string) bool {
	for _, uri := range redirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

type CreateAccessTokenService struct {
	accessTokenRepository               AccessTokenRepository
	issuer                              string
	subject                             string
	refreshTokenExpirationTimeInSeconds int
}

func NewCreateAccessTokenService(accessTokenRepository AccessTokenRepository, issuer string, subject string, refreshTokenExpirationTimeInSeconds int) CreateAccessTokenUseCase {
	return CreateAccessTokenService{accessTokenRepository: accessTokenRepository, issuer: issuer, subject: subject, refreshTokenExpirationTimeInSeconds: refreshTokenExpirationTimeInSeconds}
}

func (c CreateAccessTokenService) NewAccessToken(clientID string) (AccessToken, error) {
	accessToken := NewAccessToken(ulid.New(), c.issuer, c.subject, clientID, time.Now().Add(time.Second*time.Duration(c.refreshTokenExpirationTimeInSeconds)))
	_, err := c.accessTokenRepository.CreateAccessToken(accessToken)
	if err != nil {
		return AccessToken{}, err
	}
	return accessToken, nil
}

type CreateRefreshTokenService struct {
	refreshTokenRepository              RefreshTokenRepository
	issuer                              string
	subject                             string
	refreshTokenExpirationTimeInSeconds int
}

func NewCreateRefreshTokenService(refreshTokenRepository RefreshTokenRepository, issuer string, subject string, refreshTokenExpirationTimeInSeconds int) CreateRefreshTokenUseCase {
	return CreateRefreshTokenService{refreshTokenRepository: refreshTokenRepository, issuer: issuer, subject: subject, refreshTokenExpirationTimeInSeconds: refreshTokenExpirationTimeInSeconds}
}

func (c CreateRefreshTokenService) NewRefreshToken(clientID string) (RefreshToken, error) {
	refreshToken := NewRefreshToken(ulid.New(), c.issuer, c.subject, clientID, time.Now().Add(time.Second*time.Duration(c.refreshTokenExpirationTimeInSeconds)))
	_, err := c.refreshTokenRepository.CreateRefreshToken(refreshToken)
	if err != nil {
		return RefreshToken{}, err
	}
	return refreshToken, nil
}
