package client

type CreateClientUseCase interface {
	NewClient(redirectURI string) (Client, error)
}

type GetClientUseCase interface {
	GetClientByID(clientID string) (Client, error)
}

type DisableClientUseCase interface {
	DisableClientByID(clientID string) (Client, error)
}

type EnableClientUseCase interface {
	EnableClientByID(clientID string) (Client, error)
}

type AuthenticateClientUseCase interface {
	AuthenticateClient(clientAuthentication ClientAuthentication) (Client, error)
}

type CreateClientAccessTokenUseCase interface {
	NewClientAccessToken(clientID string, accessTokenID string) (ClientAccessToken, error)
}

type CreateClientRefreshTokenUseCase interface {
	NewClientRefreshToken(clientID string, refreshTokenID string) (ClientRefreshToken, error)
}
