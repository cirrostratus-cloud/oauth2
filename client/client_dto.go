package client

type ClientAuthentication struct {
	ClientID     string
	ClientSecret string
}

type CreateClientResult struct {
	ClientID     string
	ClientSecret string
	Enabled      bool
	RedirectURIs []string
}

type GetClientResult struct {
	ClientID     string
	Enabled      bool
	RedirectURIs []string
}

type DisabledClientResult struct {
	ClientID string
	Enabled  bool
}

type EnabledClientResult struct {
	ClientID string
	Enabled  bool
}

type AuthenticatedClientResult struct {
	ClientID string
}

type ClientByID struct {
	ClientID string
}

type CreateClient struct {
	RedirectURIs []string
}

type UpdateRedirectURIs struct {
	ClientID     string
	RedirectURIs []string
}
