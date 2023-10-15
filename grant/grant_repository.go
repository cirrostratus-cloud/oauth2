package grant

type AccessTokenRepository interface {
	FindAccessTokenByID(id string) (AccessToken, error)
	FindAccessTokenByClientID(clientID string) ([]AccessToken, error)
	FindAccessTokenByUserID(userID string) ([]AccessToken, error)
	CreateAccessToken(accessToken AccessToken) (AccessToken, error)
	DeleteAccessToken(accessToken AccessToken) error
}
