package client

type CreateClientUseCase interface {
	NewClient(CreateClient) (CreateClientResult, error)
}

type GetClientUseCase interface {
	GetClientByID(ClientByID) (GetClientResult, error)
}

type DisableClientUseCase interface {
	DisableClientByID(ClientByID) (DisabledClientResult, error)
}

type EnableClientUseCase interface {
	EnableClientByID(ClientByID) (EnabledClientResult, error)
}

type AuthenticateClientUseCase interface {
	AuthenticateClient(clientAuthentication ClientAuthentication) (AuthenticatedClientResult, error)
}

type UpdateRedirectURIsUseCase interface {
	UpdateRedirectURIs(updateRedirectURIs UpdateRedirectURIs) (UpdateRedirectURIsResult, error)
}
