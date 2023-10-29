package event

import "github.com/cirrostratus-cloud/common/event"

const (
	ClientCreatedEventName             event.EventName = "client/created"
	ClientDisabledEventName            event.EventName = "client/disabled"
	ClientEnabledEventName             event.EventName = "client/enabled"
	ClientRedirectURIsUpdatedEventName event.EventName = "client/redirect_uris_updated"
)

type ClientCreatedEvent struct {
	ClientID string
}

func (e ClientCreatedEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"clientID": e.ClientID,
	}
}

type ClientDisabledEvent struct {
	ClientID string
}

func (e ClientDisabledEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"clientID": e.ClientID,
	}
}

type ClientEnabledEvent struct {
	ClientID string
}

func (e ClientEnabledEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"clientID": e.ClientID,
	}
}

type ClientRedirectURIsUpdatedEvent struct {
	ClientID     string
	RedirectURIs []string
}

func (e ClientRedirectURIsUpdatedEvent) GetPayload() map[string]interface{} {
	return map[string]interface{}{
		"clientID":     e.ClientID,
		"redirectURIs": e.RedirectURIs,
	}
}
