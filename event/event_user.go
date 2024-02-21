package event

import "github.com/cirrostratus-cloud/common/event"

const (
	UserCreatedEventName           event.EventName = "user/created"
	UserPasswordChangedEventName   event.EventName = "user/password_changed"
	UserPasswordRecoveredEventName event.EventName = "user/password_recovered"
)

type UserCreatedEvent struct {
	UserID      string
	RawPassword string
}

func (e UserCreatedEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"userID":      e.UserID,
		"rawPassword": e.RawPassword,
	}
}

func (e UserCreatedEvent) GetName() event.EventName {
	return UserCreatedEventName
}

type PasswordChangedEvent struct {
	UserID string
}

func (e PasswordChangedEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"userID": e.UserID,
	}
}

func (e PasswordChangedEvent) GetName() event.EventName {
	return UserPasswordChangedEventName
}

type UserPasswordRecoveredEvent struct {
	UserID string
}

func (e UserPasswordRecoveredEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"userID": e.UserID,
	}
}
