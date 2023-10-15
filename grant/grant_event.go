package grant

const (
	AccessTokenCreatedEventName  = "accessToken/created"
	AccessTokenDeletedEventName  = "accessToken/deleted"
	RefreshTokenCreatedEventName = "refreshToken/created"
	RefreshTokenDeletedEventName = "refreshToken/deleted"
)

type RefreshTokenCreatedEvent struct {
	ClientID       string
	RefreshTokenID string
}

type RefreshTokenDeletedEvent struct {
	ClientID       string
	RefreshTokenID string
}

type AccessTokenCreatedEvent struct {
	ClientID      string
	AccessTokenID string
}

type AccessTokenDeletedEvent struct {
	ClientID      string
	AccessTokenID string
}

type AccessTokenPublisher interface {
	SendAccessTokenCreated(event AccessTokenCreatedEvent) error
	SendAccessTokenDeleted(event AccessTokenDeletedEvent) error
}

type RefreshTokenPublisher interface {
	SendRefreshTokenCreated(event RefreshTokenCreatedEvent) error
	SendRefreshTokenDeleted(event RefreshTokenDeletedEvent) error
}
