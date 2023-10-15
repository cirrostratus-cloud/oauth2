package util

import (
	"errors"
	"net/url"
)

var ErrInvalidURI error = errors.New("invalid URI")

func ValidateHTTPURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)

	if err != nil {
		return err
	}

	if (parsedURL.Scheme == "http" && parsedURL.Hostname() == "localhost") || parsedURL.Scheme == "https" {
		return nil
	} else {
		return ErrInvalidURI
	}
}
