package client

type ClientCreatedEvent struct {
	ClientID string
}

type ClientDeletedEvent struct {
	ClientID string
}

type ClientDisabledEvent struct {
	ClientID string
}

type ClientEnabledEvent struct {
	ClientID string
}

type ClientCreatedPublisher interface {
	ClientCreated(event ClientCreatedEvent) error
}

type ClientDeletedPublisher interface {
	ClientDeleted(event ClientDeletedEvent) error
}

type ClientDisabledPublisher interface {
	ClientDisabled(event ClientDisabledEvent) error
}

type ClientEnabledPublisher interface {
	ClientEnabled(event ClientEnabledEvent) error
}
