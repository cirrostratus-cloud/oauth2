package client

type ClientAuthentication struct {
	ClientID     string
	ClientSecret string
}

type ClientByID struct {
	ClientID string
}

type CreateClient struct {
	RedirectURIs []string
}
