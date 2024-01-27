package grant

import "time"

type jwtClaim struct {
	ID         string
	Issuer     string
	IssuedAt   time.Time
	Subject    string
	Audience   string
	Expiration time.Time
}

// Function to get expiration time in seconds from refresh token
func (j jwtClaim) GetExpirationTimeInSeconds() int {
	return int(time.Until(j.Expiration).Seconds())
}

// Function to check if refresh token is expired
func (j jwtClaim) IsExpired() bool {
	return j.Expiration.Before(time.Now())
}

// Function to get refresh token id
func (j jwtClaim) GetID() string {
	return j.ID
}

// Function to get refresh token issuer
func (j jwtClaim) GetIssuer() string {
	return j.Issuer
}

// Function to get refresh token subject
func (j jwtClaim) GetSubject() string {
	return j.Subject
}

// Function to get refresh token audience
func (j jwtClaim) GetAudience() string {
	return j.Audience
}

func newJwtClaim(id string, iss string, sub string, clientID string, exp time.Time) jwtClaim {
	return jwtClaim{
		ID:         id,
		Issuer:     iss,
		IssuedAt:   time.Now(),
		Subject:    sub,
		Audience:   clientID,
		Expiration: exp,
	}
}

// RefreshToken is a struct to represent refresh token
type RefreshToken struct {
	jwtClaim
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

func NewRefreshToken(id string, iss string, sub string, clientID string, exp time.Time) RefreshToken {
	return RefreshToken{
		jwtClaim: newJwtClaim(id, iss, sub, clientID, exp),
		revoked:  false,
	}
}

// AccessToken is a struct to represent access token
type AccessToken struct {
	jwtClaim
	additionalData map[string]interface{}
	revoked        bool
}

func GetAdditionalDataByKeyName(additionalData map[string]interface{}, keyName string) interface{} {
	if additionalData == nil {
		return nil
	}

	return additionalData[keyName]
}

func HasAdditionalDataKey(additionalData map[string]interface{}, keyName string) bool {
	if additionalData == nil {
		return false
	}

	_, ok := additionalData[keyName]
	return ok
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
func (a AccessToken) GetAdditionalData() map[string]interface{} {
	return a.additionalData
}

func NewAccessToken(id string, iss string, sub string, clientID string, exp time.Time) AccessToken {
	return AccessToken{
		jwtClaim:       newJwtClaim(id, iss, sub, clientID, exp),
		additionalData: make(map[string]interface{}),
	}
}
