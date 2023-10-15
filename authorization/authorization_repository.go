package authorization

type AuthorizationSessionRepository interface {
	CreateAuthorizationSession(auhtorizationSession AuthorizationSession) (AuthorizationSession, error)
	FindAuthorizationSessionByID(sessionID string) (AuthorizationSession, error)
	FindAuthorizationSessionByCode(code string) (AuthorizationSession, error)
	UpdateAuthorizationCodeByID(sessionID string, code string) error
}

type AuthorizationCodeRepository interface {
	CreateAuthorizationCode(AuthorizationCode) (AuthorizationCode, error)
	FindAuthorizationCodeByCode(code string) (AuthorizationCode, error)
}
