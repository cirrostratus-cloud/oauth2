package grant

type AuthorizationUserAgentUseCase interface {
	AuthorizeWithUserAgentParams(authorizationCodeUserAgentRequest AuthorizationCodeUserAgentRequest) (AuthorizationCodeUserAgentResponse, error)
}

type AuthorizationCodeGrantUseCase interface {
	AuthorizeWithCode(authorizationCode AuthorizationCodeRequest) (AuthorizationCodeResponse, error)
}

type ImplicitGrantUseCase interface {
	AuthorizeImplicitWithUserAgentParams(implicit ImplicitUserAgentRequest) (ImplicitUserAgentResponse, error)
}

type PasswordCredentialsGrantUseCase interface {
	AuthorizeWithPasswordCredentials(resourceOwnerPasswordCredentials ResourceOwnerPasswordCredentialsRequest) (ResourceOwnerPasswordCredentialsResponse, error)
}

type ClientCredentialsGrantUseCase interface {
	AuthorizeWithClientCredentials(clientCredentials ClientCredentialsRequest) (ClientCredentialsResponse, error)
}

type CreateAccessTokenUseCase interface {
	NewAccessToken(clientID string, userID string, scope string) (AccessToken, error)
}

type CreateRefreshTokenUseCase interface {
	NewRefreshToken(clientID string, userID string, scope string) (RefreshToken, error)
}

type RefreshAccessTokenUseCase interface {
	RefreshAccessToken(refreshToken string) (AccessTokenResponse, error)
}
