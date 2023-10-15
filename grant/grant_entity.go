package grant

import "time"

// RefreshToken is a struct to represent refresh token
type RefreshToken struct {
	revoked bool
}

// Function to revoke refresh token
func (a *RefreshToken) Revoke() {
	a.revoked = true
}

// Function to check if refresh token is revoked
func (a RefreshToken) IsRevoked() bool {
	return a.revoked
}

// AccessToken is a struct to represent access token
type AccessToken struct {
	id             string
	iss            string
	iat            time.Time
	sub            string
	aud            string
	exp            time.Time
	additionalData map[string]interface{}
	revoked        bool
}

// Function to revoke access token
func (a *AccessToken) Revoke() {
	a.revoked = true
}

// Function to check if access token is revoked
func (a AccessToken) IsRevoked() bool {
	return a.revoked
}

// Function to get additional data from access token
func (a AccessToken) GetAdditionalData(key string) interface{} {
	return a.additionalData[key]
}

// Function to get expiration time in seconds from access token
func (a AccessToken) GetExpirationTimeInSeconds() int {
	return int(time.Until(a.exp).Seconds())
}

// Function to check if access token is expired
func (a AccessToken) IsExpired() bool {
	return a.exp.Before(time.Now())
}

// Function to get access token id
func (a AccessToken) GetID() string {
	return a.id
}

// Function to get access token issuer
func (a AccessToken) GetIssuer() string {
	return a.iss
}

// Function to get access token subject
func (a AccessToken) GetSubject() string {
	return a.sub
}

// Function to get access token audience
func (a AccessToken) GetAudience() string {
	return a.aud
}

func NewAccessToken(id string, iss string, sub string, clientID string, exp time.Time) AccessToken {
	return AccessToken{
		id:             id,
		iss:            iss,
		aud:            clientID,
		sub:            sub,
		iat:            time.Now(),
		exp:            exp,
		additionalData: make(map[string]interface{}),
	}
}
