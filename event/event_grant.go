package event

import "github.com/cirrostratus-cloud/common/event"

const (
	AccessTokenCreatedEventName  event.EventName = "accessToken/created"
	AccessTokenDeletedEventName  event.EventName = "accessToken/deleted"
	RefreshTokenCreatedEventName event.EventName = "refreshToken/created"
	RefreshTokenDeletedEventName event.EventName = "refreshToken/deleted"
)

type RefreshTokenCreatedEvent struct {
	ClientID       string
	RefreshTokenID string
}

func (r RefreshTokenCreatedEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"clientID":       r.ClientID,
		"refreshTokenID": r.RefreshTokenID,
	}
}

type RefreshTokenDeletedEvent struct {
	ClientID       string
	RefreshTokenID string
}

func (r RefreshTokenDeletedEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"clientID":       r.ClientID,
		"refreshTokenID": r.RefreshTokenID,
	}
}

type AccessTokenCreatedEvent struct {
	ClientID      string
	AccessTokenID string
}

func (a AccessTokenCreatedEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"clientID":      a.ClientID,
		"accessTokenID": a.AccessTokenID,
	}
}

type AccessTokenDeletedEvent struct {
	ClientID      string
	AccessTokenID string
}

func (a AccessTokenDeletedEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"clientID":      a.ClientID,
		"accessTokenID": a.AccessTokenID,
	}
}
