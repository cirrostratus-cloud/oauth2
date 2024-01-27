package grant

import "github.com/cirrostratus-cloud/oauth2/user"

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
	NewAccessToken(clientID string) (AccessToken, error)
}

type CreateRefreshTokenUseCase interface {
	NewRefreshToken(clientID string) (RefreshToken, error)
}

type RefreshAccessTokenUseCase interface {
	RefreshAccessToken(refreshToken string) (AccessTokenResponse, error)
}

type GetAdditionalDataUseCase interface {
	GetAdditionalData(user.User) (map[string]interface{}, error)
}
