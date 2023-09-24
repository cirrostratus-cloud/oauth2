package client

import "errors"

var ErrClientIDEmpty error = errors.New("Client ID is empty")
var ErrClientSecretEmpty error = errors.New("Client Secret is empty")
var ErrClientRedirectURIEmpty error = errors.New("Client Redirect URI is empty")
var ErrClientDisabled error = errors.New("Client is disabled")
