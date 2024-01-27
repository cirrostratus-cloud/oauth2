package authorization

type SessionGrantRequest struct {
	RedirectURI string
	State       string
}

type SessionGrantResponse struct {
	SessionID      string
	ExpirationTime int
}

type AuthorizationCodeGrantRequest struct {
	Code        string
	ClientID    string
	RedirectURI string
}

type AuthorizationCodeGrantResponse struct {
	ClientID string
	Code     string
}

type SessionByID struct {
	SessionID string
}

type AuthorizationSessionResponse struct {
	RedirectURI string
	State       string
	ExpiresIn   int
}
