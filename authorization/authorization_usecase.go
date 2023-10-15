package authorization

type GetAuthorizationSessionUseCase interface {
	GetAuthorizationSessionByID(sessionID string) (AuthorizationSession, error)
}

type CreateAuthorizationCodeUseCase interface {
	NewAuthorizationCode(code string, redirectionURI string, clientID string) (AuthorizationCode, error)
}

type GetAuthorizationCodeUseCase interface {
	GetAuthorizationCodeByCode(code string) (AuthorizationCode, error)
}

type CreateAuthorizationSessionUseCase interface {
	NewAuthorizationSession(redirectURI string, state string) (SessionGrant, error)
}
