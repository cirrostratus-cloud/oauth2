package client

type CreateClientUseCase interface {
	NewClient(CreateClient) (Client, error)
}

type GetClientUseCase interface {
	GetClientByID(ClientByID) (Client, error)
}

type DisableClientUseCase interface {
	DisableClientByID(ClientByID) (Client, error)
}

type EnableClientUseCase interface {
	EnableClientByID(ClientByID) (Client, error)
}

type AuthenticateClientUseCase interface {
	AuthenticateClient(clientAuthentication ClientAuthentication) (Client, error)
}
