package authorization

import (
	"errors"
	"time"

	"github.com/cirrostratus-cloud/common/uuid"
	"github.com/cirrostratus-cloud/oauth2/util"
	log "github.com/sirupsen/logrus"
)

var ErrAuthorizationSessionExpired = errors.New("authorization session expired")
var ErrAuthorizationCodeExpired = errors.New("authorization code expired")
var ErrClientIDMismatch = errors.New("client id mismatch")
var ErrRedirectURIMismatch = errors.New("redirect uri mismatch")

type CreateAuthorizationSessionService struct {
	authorizationSessionRepository AuthorizationSessionRepository
	maxAgeInSeconds                int
}

func NewCreateAuthorizationSessionService(authorizationSessionRepository AuthorizationSessionRepository, maxAgeInSeconds int) CreateAuthorizationSessionUseCase {
	return CreateAuthorizationSessionService{authorizationSessionRepository: authorizationSessionRepository, maxAgeInSeconds: maxAgeInSeconds}
}

func (a CreateAuthorizationSessionService) NewAuthorizationSession(sessionGrantRequest SessionGrantRequest) (SessionGrantResponse, error) {
	err := util.ValidateHTTPURL(sessionGrantRequest.RedirectURI)
	if err != nil {
		return SessionGrantResponse{}, err
	}
	authorizationSession := NewAuthorizationSession(
		uuid.NewV4(),
		time.Now().Add(time.Duration(a.maxAgeInSeconds)*time.Second),
		sessionGrantRequest.RedirectURI,
		sessionGrantRequest.State,
	)
	_, err = a.authorizationSessionRepository.CreateAuthorizationSession(authorizationSession)
	if err != nil {
		return SessionGrantResponse{}, err
	}
	return SessionGrantResponse{
		SessionID:      authorizationSession.GetID(),
		ExpirationTime: authorizationSession.GetExpirationTimeInSeconds(),
	}, nil
}

type GetAuthorizationSessionService struct {
	authorizationSessionRepository AuthorizationSessionRepository
}

func NewGetAuthorizationSessionService(authorizationSessionRepository AuthorizationSessionRepository) GetAuthorizationSessionUseCase {
	return GetAuthorizationSessionService{authorizationSessionRepository: authorizationSessionRepository}
}

func (a GetAuthorizationSessionService) GetAuthorizationSessionByID(sessionByID SessionByID) (AuthorizationSessionResponse, error) {
	authorizationSession, err := a.authorizationSessionRepository.FindAuthorizationSessionByID(sessionByID.SessionID)
	if err != nil {
		return AuthorizationSessionResponse{}, err
	}
	if authorizationSession.IsExpired() {
		return AuthorizationSessionResponse{}, ErrAuthorizationSessionExpired
	}
	return AuthorizationSessionResponse{
		RedirectURI: authorizationSession.GetRedirectionURI(),
		State:       authorizationSession.GetState(),
		ExpiresIn:   authorizationSession.GetExpirationTimeInSeconds(),
	}, nil
}

type CreateAuthorizationCodeService struct {
	authorizationAuthorizationCodeRepository AuthorizationCodeRepository
	expirationTime                           time.Time
	codeLenght                               int
}

func (a CreateAuthorizationCodeService) NewAuthorizationCode(authorizationCodeGrant AuthorizationCodeGrantRequest) (AuthorizationCodeGrantResponse, error) {
	err := util.ValidateHTTPURL(authorizationCodeGrant.RedirectURI)
	if err != nil {
		log.WithFields(log.Fields{
			"redirect_uri": authorizationCodeGrant.RedirectURI,
		}).Error("Invalid redirect URI")
		return AuthorizationCodeGrantResponse{}, err
	}
	authorizationAuthorizationCode := NewAuthorizationCode(util.NewRandomCode(a.codeLenght), authorizationCodeGrant.RedirectURI, a.expirationTime, authorizationCodeGrant.ClientID)
	authorizationAuthorizationCode, err = a.authorizationAuthorizationCodeRepository.CreateAuthorizationCode(authorizationAuthorizationCode)
	if err != nil {
		return AuthorizationCodeGrantResponse{}, err
	}
	return AuthorizationCodeGrantResponse{
		Code: authorizationAuthorizationCode.GetCode(),
	}, nil
}

func NewCreateAuthorizationCodeService(authorizationAuthorizationCodeRepository AuthorizationCodeRepository, expirationTime time.Time, codeLenght int) CreateAuthorizationCodeUseCase {
	return CreateAuthorizationCodeService{authorizationAuthorizationCodeRepository: authorizationAuthorizationCodeRepository, expirationTime: expirationTime, codeLenght: codeLenght}
}

type GetAuthorizationCodeService struct {
	authorizationAuthorizationCodeRepository AuthorizationCodeRepository
}

func NewGetAuthorizationCodeService(authorizationAuthorizationCodeRepository AuthorizationCodeRepository) GetAuthorizationCodeUseCase {
	return GetAuthorizationCodeService{authorizationAuthorizationCodeRepository: authorizationAuthorizationCodeRepository}
}

func (a GetAuthorizationCodeService) GetAuthorizationCodeByCode(authorizationCodeGrant AuthorizationCodeGrantRequest) (AuthorizationCodeGrantResponse, error) {
	authorizationAuthorizationCode, err := a.authorizationAuthorizationCodeRepository.FindAuthorizationCodeByCode(authorizationCodeGrant.Code)
	if err != nil {
		return AuthorizationCodeGrantResponse{}, err
	}
	if authorizationAuthorizationCode.IsExpired() {
		return AuthorizationCodeGrantResponse{}, ErrAuthorizationCodeExpired
	}
	if authorizationAuthorizationCode.GetClientID() != authorizationCodeGrant.ClientID {
		return AuthorizationCodeGrantResponse{}, ErrClientIDMismatch
	}
	if authorizationAuthorizationCode.GetRedirectionURI() != authorizationCodeGrant.RedirectURI {
		return AuthorizationCodeGrantResponse{}, ErrRedirectURIMismatch
	}
	return AuthorizationCodeGrantResponse{
		Code:     authorizationAuthorizationCode.GetCode(),
		ClientID: authorizationAuthorizationCode.GetClientID(),
	}, nil
}
