package client

type ClientRepository interface {
	FindClientByID(clientID string) (Client, error)
	FindClientByHashedSecret(clientSecret string) (Client, error)
	CreateClient(client Client) (Client, error)
	UpdateClient(client Client) (Client, error)
	DeleteClientByID(clientID string) error
}
