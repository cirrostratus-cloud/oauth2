package grant

type ClientCredentials struct {
	ClientID     string
	ClientSecret string
}

type AuthorizationCodeUserAgentRequest struct {
	ClientID     string
	ResponseType string
	RedirectURI  string
	Scope        string
	State        string
}

type AuthorizationCodeUserAgentResponse struct {
	Code        string
	ErrorCode   ErrorCode
	RedirectURI string
	State       string
}

type AuthorizationCodeRequest struct {
	ClientCredentials
	GrantType   string
	RedirectURI string
	Code        string
}

type AuthorizationCodeResponse struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresIn    int
	Scope        string
}

type ImplicitUserAgentRequest struct {
	ClientID     string
	ResponseType string
	RedirectURI  string
	Scope        string
	State        string
}

type ImplicitUserAgentResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Scope       string
	State       string
	RedirectURI string
	ErrorCode   ErrorCode
}

type ClientCredentialsRequest struct {
	ClientCredentials
	GrantType string
	Scope     string
}

type ClientCredentialsResponse struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	Scope        string
}

type ResourceOwnerPasswordCredentialsRequest struct {
	ClientCredentials
	GrantType string
	Username  string
	Password  string
	Scope     string
}

type ResourceOwnerPasswordCredentialsResponse struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresIn    int
	Scope        string
}

type AccessTokenResponse struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	ExpiresIn    int
	Scope        string
}

type RefreshTokenRequest struct {
	ClientCredentials
	GrantType    string
	RefreshToken string
	Scope        string
}
