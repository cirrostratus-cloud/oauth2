package grant

type AccessTokenRepository interface {
	FindAccessTokenByID(id string) (AccessToken, error)
	FindAccessTokenByClientID(clientID string) ([]AccessToken, error)
	FindAccessTokenByUserID(userID string) ([]AccessToken, error)
	CreateAccessToken(accessToken AccessToken) (AccessToken, error)
	DeleteAccessToken(accessToken AccessToken) error
}

type RefreshTokenRepository interface {
	FindRefreshTokenByID(id string) (RefreshToken, error)
	FindRefreshTokenByClientID(clientID string) ([]RefreshToken, error)
	FindRefreshTokenByUserID(userID string) ([]RefreshToken, error)
	CreateRefreshToken(refreshToken RefreshToken) (RefreshToken, error)
	DeleteRefreshToken(refreshToken RefreshToken) error
}
