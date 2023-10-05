package client

import "github.com/cirrostratus-cloud/common/event"

const (
	ClientCreatedEventName  = "client/created"
	ClientDisabledEventName = "client/disabled"
	ClientEnabledEventName  = "client/enabled"
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

type ClientCreatedPublisher interface {
	ClientCreated(event ClientCreatedEvent) error
}

type clientCreatedPublisher struct {
	eventBus event.EventBus
}

func NewClientCreatedPublisher(eventBus event.EventBus) ClientCreatedPublisher {
	return &clientCreatedPublisher{eventBus: eventBus}
}

func (p *clientCreatedPublisher) ClientCreated(clientCreatedEvent ClientCreatedEvent) error {
	return p.eventBus.Publish(ClientCreatedEventName, clientCreatedEvent)
}

type ClientDisabledPublisher interface {
	ClientDisabled(event ClientDisabledEvent) error
}

type clientDisabledPublisher struct {
	eventBus event.EventBus
}

func NewClientDisabledPublisher(eventBus event.EventBus) ClientDisabledPublisher {
	return &clientDisabledPublisher{eventBus: eventBus}
}

func (p *clientDisabledPublisher) ClientDisabled(clientDisabledEvent ClientDisabledEvent) error {
	return p.eventBus.Publish(ClientDisabledEventName, clientDisabledEvent)
}

type ClientEnabledPublisher interface {
	ClientEnabled(event ClientEnabledEvent) error
}

type clientEnabledPublisher struct {
	eventBus event.EventBus
}

func NewClientEnabledPublisher(eventBus event.EventBus) ClientEnabledPublisher {
	return &clientEnabledPublisher{eventBus: eventBus}
}

func (p *clientEnabledPublisher) ClientEnabled(clientEnabledEvent ClientEnabledEvent) error {
	return p.eventBus.Publish(ClientEnabledEventName, clientEnabledEvent)
}
