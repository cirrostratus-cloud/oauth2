package util

import (
	"errors"
	"net/url"
)

var ErrInvalidRedirectURI error = errors.New("invalid redirect URI")

func ValidateHTTPURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)

	if err != nil {
		return ErrInvalidRedirectURI
	}

	if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
		return nil
	} else {
		return ErrInvalidRedirectURI
	}
}
