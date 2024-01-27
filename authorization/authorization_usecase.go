package authorization

type GetAuthorizationSessionUseCase interface {
	GetAuthorizationSessionByID(SessionByID) (AuthorizationSessionResponse, error)
}

type CreateAuthorizationCodeUseCase interface {
	NewAuthorizationCode(AuthorizationCodeGrantRequest) (AuthorizationCodeGrantResponse, error)
}

type GetAuthorizationCodeUseCase interface {
	GetAuthorizationCodeByCode(AuthorizationCodeGrantRequest) (AuthorizationCodeGrantResponse, error)
}

type CreateAuthorizationSessionUseCase interface {
	NewAuthorizationSession(SessionGrantRequest) (SessionGrantResponse, error)
}
