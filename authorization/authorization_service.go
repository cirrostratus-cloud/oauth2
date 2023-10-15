package authorization

import (
	"errors"
	"time"

	"github.com/cirrostratus-cloud/common/uuid"
	"github.com/cirrostratus-cloud/oauth2/util"
)

var ErrAuthorizationSessionExpired = errors.New("authorization session expired")

type CreateAuthorizationSessionService struct {
	authorizationSessionRepository AuthorizationSessionRepository
	maxAgeInSeconds                int
}

func NewCreateAuthorizationSessionService(authorizationSessionRepository AuthorizationSessionRepository, maxAgeInSeconds int) CreateAuthorizationSessionUseCase {
	return CreateAuthorizationSessionService{authorizationSessionRepository: authorizationSessionRepository, maxAgeInSeconds: maxAgeInSeconds}
}

func (a CreateAuthorizationSessionService) NewAuthorizationSession(redirectURI string, state string) (SessionGrant, error) {
	err := util.ValidateHTTPURL(redirectURI)
	if err != nil {
		return SessionGrant{}, err
	}
	authorizationSession := NewAuthorizationSession(uuid.NewV4(), time.Now().Add(time.Duration(a.maxAgeInSeconds)*time.Second), redirectURI, state)
	_, err = a.authorizationSessionRepository.CreateAuthorizationSession(authorizationSession)
	if err != nil {
		return SessionGrant{}, err
	}
	return SessionGrant{SessionID: authorizationSession.GetID(), ExpirationTime: authorizationSession.GetExpirationTimeInSeconds()}, nil
}

type GetAuthorizationSessionService struct {
	authorizationSessionRepository AuthorizationSessionRepository
}

func NewGetAuthorizationSessionService(authorizationSessionRepository AuthorizationSessionRepository) GetAuthorizationSessionUseCase {
	return GetAuthorizationSessionService{authorizationSessionRepository: authorizationSessionRepository}
}

func (a GetAuthorizationSessionService) GetAuthorizationSessionByID(sessionID string) (AuthorizationSession, error) {
	authorizationSession, err := a.authorizationSessionRepository.FindAuthorizationSessionByID(sessionID)
	if err != nil {
		return AuthorizationSession{}, err
	}
	if authorizationSession.IsExpired() {
		return AuthorizationSession{}, ErrAuthorizationSessionExpired
	}
	return authorizationSession, nil
}

type CreateAuthorizationCodeService struct {
	authorizationAuthorizationCodeRepository AuthorizationCodeRepository
	expirationTime                           time.Time
}

func (a CreateAuthorizationCodeService) NewAuthorizationCode(code string, redirectionURI string, clientID string) (AuthorizationCode, error) {
	err := util.ValidateHTTPURL(redirectionURI)
	if err != nil {
		return AuthorizationCode{}, err
	}
	authorizationAuthorizationCode := NewAuthorizationCode(code, redirectionURI, a.expirationTime, clientID)
	authorizationAuthorizationCode, err = a.authorizationAuthorizationCodeRepository.CreateAuthorizationCode(authorizationAuthorizationCode)
	if err != nil {
		return AuthorizationCode{}, err
	}
	return authorizationAuthorizationCode, nil
}

func NewCreateAuthorizationCodeService(authorizationAuthorizationCodeRepository AuthorizationCodeRepository, expirationTime time.Time) CreateAuthorizationCodeUseCase {
	return CreateAuthorizationCodeService{authorizationAuthorizationCodeRepository: authorizationAuthorizationCodeRepository, expirationTime: expirationTime}
}
