package authorization_test

import (
	"errors"
	"testing"
	"time"

	"github.com/cirrostratus-cloud/oauth2/authorization"
	mauthorization "github.com/cirrostratus-cloud/oauth2/mocks/github.com/cirrostratus-cloud/oauth2/authorization"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewAuthorizationSessionSuccess(t *testing.T) {
	assert := assert.New(t)
	authorizationSessionRepository := mauthorization.NewMockAuthorizationSessionRepository(t)
	authorizationSessionRepository.
		On("CreateAuthorizationSession", mock.AnythingOfType("authorization.AuthorizationSession")).
		Return(func(authorizationSession authorization.AuthorizationSession) (authorization.AuthorizationSession, error) {
			return authorizationSession, nil
		})
	expirationTime := 300
	createAuthorizationSessionService := authorization.NewCreateAuthorizationSessionService(
		authorizationSessionRepository,
		expirationTime,
	)
	sessionGrantRequest := authorization.SessionGrantRequest{
		RedirectURI: "http://localhost:8080",
		State:       "state",
	}
	sessionGrantResponse, err := createAuthorizationSessionService.NewAuthorizationSession(sessionGrantRequest)
	assert.Nil(err)
	assert.True(sessionGrantResponse.ExpirationTime > 0, "Expiration time should be greater than 0")
}

func TestNewAuthorizationSessionInvalidRedirectURI(t *testing.T) {
	assert := assert.New(t)
	authorizationSessionRepository := mauthorization.
		NewMockAuthorizationSessionRepository(t)
	expirationTime := 300
	createAuthorizationSessionService := authorization.NewCreateAuthorizationSessionService(
		authorizationSessionRepository,
		expirationTime,
	)
	sessionGrantRequest := authorization.SessionGrantRequest{
		RedirectURI: "http://localhost:8080`",
		State:       "state",
	}
	_, err := createAuthorizationSessionService.NewAuthorizationSession(sessionGrantRequest)
	assert.NotNil(err)
}

func TestGetAuthorizationSessionByIDSuccess(t *testing.T) {
	assert := assert.New(t)
	authorizationSessionRepository := mauthorization.
		NewMockAuthorizationSessionRepository(t)
	authorizationSessionRepository.
		On("FindAuthorizationSessionByID",
			mock.MatchedBy(func(sessionID string) bool {
				return sessionID == "sessionID"
			})).
		Return(func(sessionID string) (authorization.AuthorizationSession, error) {
			return authorization.NewAuthorizationSession(
				sessionID,
				time.Now(),
				"http://localhost:8080",
				"state",
			), nil
		})
	getAuthorizationSessionService := authorization.NewGetAuthorizationSessionService(
		authorizationSessionRepository,
	)
	sessionByID := authorization.SessionByID{
		SessionID: "sessionID",
	}
	authorizationSessionResponse, err := getAuthorizationSessionService.GetAuthorizationSessionByID(sessionByID)
	assert.Nil(err)
	assert.Equal("http://localhost:8080", authorizationSessionResponse.RedirectURI)
	assert.Equal("state", authorizationSessionResponse.State)
	assert.True(authorizationSessionResponse.ExpiresIn > 0, "Expiration time should be greater than 0")
}

func TestGetAuthorizationSessionByIDExpired(t *testing.T) {
	assert := assert.New(t)
	authorizationSessionRepository := mauthorization.
		NewMockAuthorizationSessionRepository(t)
	authorizationSessionRepository.
		On("FindAuthorizationSessionByID",
			mock.MatchedBy(func(sessionID string) bool {
				return sessionID == "sessionID"
			})).
		Return(func(sessionID string) (authorization.AuthorizationSession, error) {
			return authorization.NewAuthorizationSession(
				sessionID,
				time.Now().Add(time.Duration(1)*time.Second),
				"http://localhost:8080",
				"state",
			), nil
		})
	time.Sleep(2 * time.Second)
	getAuthorizationSessionService := authorization.NewGetAuthorizationSessionService(
		authorizationSessionRepository,
	)
	sessionByID := authorization.SessionByID{
		SessionID: "sessionID",
	}
	_, err := getAuthorizationSessionService.GetAuthorizationSessionByID(sessionByID)
	assert.NotNil(err)
	assert.Equal(err, authorization.ErrAuthorizationSessionExpired)
}

func TestGetAuthorizationSessionByIDNotFound(t *testing.T) {
	assert := assert.New(t)
	authorizationSessionRepository := mauthorization.
		NewMockAuthorizationSessionRepository(t)
	authorizationSessionRepository.
		On("FindAuthorizationSessionByID",
			mock.AnythingOfType("string")).
		Return(func(sessionID string) (authorization.AuthorizationSession, error) {
			return authorization.AuthorizationSession{}, authorization.ErrAuthorizationSessionNotFound
		})
	getAuthorizationSessionService := authorization.NewGetAuthorizationSessionService(
		authorizationSessionRepository,
	)
	sessionByID := authorization.SessionByID{
		SessionID: "sessionID",
	}
	_, err := getAuthorizationSessionService.GetAuthorizationSessionByID(sessionByID)
	assert.NotNil(err)
	assert.Equal(err, authorization.ErrAuthorizationSessionNotFound)
}

func TestNewAuthorizationCodeSuccess(t *testing.T) {
	assert := assert.New(t)
	authorizationCodeRepository := mauthorization.
		NewMockAuthorizationCodeRepository(t)
	authorizationCodeRepository.
		On("CreateAuthorizationCode",
			mock.AnythingOfType("authorization.AuthorizationCode")).
		Return(func(authorizationCode authorization.AuthorizationCode) (authorization.AuthorizationCode, error) {
			return authorizationCode, nil
		})
	expirationTime := 300
	createAuthorizationCodeService := authorization.NewCreateAuthorizationCodeService(
		authorizationCodeRepository,
		time.Now().Add(time.Duration(expirationTime)*time.Second),
		10,
	)
	authorizationCodeRequest := authorization.AuthorizationCodeGrantRequest{
		ClientID:    "clientID",
		RedirectURI: "http://localhost:8080",
		Code:        "code",
	}
	authorizationCodeResponse, err := createAuthorizationCodeService.NewAuthorizationCode(authorizationCodeRequest)
	assert.Nil(err)
	assert.NotNilf(authorizationCodeResponse.Code, "Code should not be nil")
}

func TestNewAuthorizationCodeInvalidRedirectURI(t *testing.T) {
	assert := assert.New(t)
	authorizationCodeRepository := mauthorization.
		NewMockAuthorizationCodeRepository(t)
	expirationTime := 300
	createAuthorizationCodeService := authorization.NewCreateAuthorizationCodeService(
		authorizationCodeRepository,
		time.Now().Add(time.Duration(expirationTime)*time.Second),
		10,
	)
	authorizationCodeRequest := authorization.AuthorizationCodeGrantRequest{
		ClientID:    "clientID",
		RedirectURI: "http://localhost:8080`",
		Code:        "code",
	}
	_, err := createAuthorizationCodeService.NewAuthorizationCode(authorizationCodeRequest)
	assert.NotNil(err)
}

func TestNewAuthorizationCodeCreateError(t *testing.T) {
	assert := assert.New(t)
	authorizationCodeRepository := mauthorization.
		NewMockAuthorizationCodeRepository(t)
	authorizationCodeRepository.
		On("CreateAuthorizationCode",
			mock.AnythingOfType("authorization.AuthorizationCode")).
		Return(func(authorizationCode authorization.AuthorizationCode) (authorization.AuthorizationCode, error) {
			return authorization.AuthorizationCode{}, errors.New("error")
		})
	expirationTime := 300
	createAuthorizationCodeService := authorization.NewCreateAuthorizationCodeService(
		authorizationCodeRepository,
		time.Now().Add(time.Duration(expirationTime)*time.Second),
		10,
	)
	authorizationCodeRequest := authorization.AuthorizationCodeGrantRequest{
		ClientID:    "clientID",
		RedirectURI: "http://localhost:8080",
		Code:        "code",
	}
	_, err := createAuthorizationCodeService.NewAuthorizationCode(authorizationCodeRequest)
	assert.NotNil(err)
}

func TestGetAuthorizationCodeSuccess(t *testing.T) {
	assert := assert.New(t)
	authorizationCodeRepository := mauthorization.
		NewMockAuthorizationCodeRepository(t)
	authorizationCodeRepository.
		On("FindAuthorizationCodeByCode",
			mock.MatchedBy(func(code string) bool {
				return code == "code"
			})).
		Return(func(code string) (authorization.AuthorizationCode, error) {
			return authorization.NewAuthorizationCode(
				code,
				"http://localhost:8080",
				time.Now().Add(-(time.Duration(300) * time.Second)),
				"clientID",
			), nil
		})
	getAuthorizationCodeService := authorization.NewGetAuthorizationCodeService(
		authorizationCodeRepository,
	)
	authorizationCodeRequest := authorization.AuthorizationCodeGrantRequest{
		Code:        "code",
		ClientID:    "clientID",
		RedirectURI: "http://localhost:8080",
	}
	authorizationCodeResponse, err := getAuthorizationCodeService.GetAuthorizationCodeByCode(authorizationCodeRequest)
	assert.Nil(err)
	assert.Equal("code", authorizationCodeResponse.Code)
	assert.Equal("clientID", authorizationCodeResponse.ClientID)
}

func TestGetAuthorizationCodeExpired(t *testing.T) {
	assert := assert.New(t)
	authorizationCodeRepository := mauthorization.
		NewMockAuthorizationCodeRepository(t)
	authorizationCodeRepository.
		On("FindAuthorizationCodeByCode",
			mock.MatchedBy(func(code string) bool {
				return code == "code"
			})).
		Return(func(code string) (authorization.AuthorizationCode, error) {
			return authorization.NewAuthorizationCode(
				code,
				"http://localhost:8080",
				time.Now().Add(time.Duration(1)*time.Second),
				"clientID",
			), nil
		})
	time.Sleep(2 * time.Second)
	getAuthorizationCodeService := authorization.NewGetAuthorizationCodeService(
		authorizationCodeRepository,
	)
	authorizationCodeRequest := authorization.AuthorizationCodeGrantRequest{
		Code: "code",
	}
	_, err := getAuthorizationCodeService.GetAuthorizationCodeByCode(authorizationCodeRequest)
	assert.NotNil(err)
	assert.Equal(err, authorization.ErrAuthorizationCodeExpired)
}

func TestGetAuthorizationCodeNotFound(t *testing.T) {
	assert := assert.New(t)
	authorizationCodeRepository := mauthorization.
		NewMockAuthorizationCodeRepository(t)
	authorizationCodeRepository.
		On("FindAuthorizationCodeByCode",
			mock.AnythingOfType("string")).
		Return(func(code string) (authorization.AuthorizationCode, error) {
			return authorization.AuthorizationCode{}, errors.New("error")
		})
	getAuthorizationCodeService := authorization.NewGetAuthorizationCodeService(
		authorizationCodeRepository,
	)
	authorizationCodeRequest := authorization.AuthorizationCodeGrantRequest{
		Code:        "code",
		ClientID:    "clientID",
		RedirectURI: "http://localhost:8080",
	}
	_, err := getAuthorizationCodeService.GetAuthorizationCodeByCode(authorizationCodeRequest)
	assert.NotNil(err)
	assert.Equal(err, errors.New("error"))
}

func TestGetAuthorizationCodeClientIDMismatch(t *testing.T) {
	assert := assert.New(t)
	authorizationCodeRepository := mauthorization.
		NewMockAuthorizationCodeRepository(t)
	authorizationCodeRepository.
		On("FindAuthorizationCodeByCode",
			mock.MatchedBy(func(code string) bool {
				return code == "code"
			})).
		Return(func(code string) (authorization.AuthorizationCode, error) {
			return authorization.NewAuthorizationCode(
				code,
				"http://localhost:8080",
				time.Now().Add(-(time.Duration(300) * time.Second)),
				"clientID",
			), nil
		})
	getAuthorizationCodeService := authorization.NewGetAuthorizationCodeService(
		authorizationCodeRepository,
	)
	authorizationCodeRequest := authorization.AuthorizationCodeGrantRequest{
		Code:        "code",
		ClientID:    "clientID2",
		RedirectURI: "http://localhost:8080",
	}
	_, err := getAuthorizationCodeService.GetAuthorizationCodeByCode(authorizationCodeRequest)
	assert.NotNil(err)
	assert.Equal(err, authorization.ErrClientIDMismatch)
}

func TestGetAuthorizationCodeRedirectURIMismatch(t *testing.T) {
	assert := assert.New(t)
	authorizationCodeRepository := mauthorization.
		NewMockAuthorizationCodeRepository(t)
	authorizationCodeRepository.
		On("FindAuthorizationCodeByCode",
			mock.MatchedBy(func(code string) bool {
				return code == "code"
			})).
		Return(func(code string) (authorization.AuthorizationCode, error) {
			return authorization.NewAuthorizationCode(
				code,
				"http://localhost:8080",
				time.Now().Add(-(time.Duration(300) * time.Second)),
				"clientID",
			), nil
		})
	getAuthorizationCodeService := authorization.NewGetAuthorizationCodeService(
		authorizationCodeRepository,
	)
	authorizationCodeRequest := authorization.AuthorizationCodeGrantRequest{
		Code:        "code",
		ClientID:    "clientID",
		RedirectURI: "http://localhost:8080`",
	}
	_, err := getAuthorizationCodeService.GetAuthorizationCodeByCode(authorizationCodeRequest)
	assert.NotNil(err)
	assert.Equal(err, authorization.ErrRedirectURIMismatch)
}
