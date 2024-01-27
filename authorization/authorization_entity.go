package authorization

import "time"

// AuthorizationSession is a struct to represent authorization session
type AuthorizationSession struct {
	id             string
	expirationTime time.Time
	redirectionURI string
	state          string
}

// Function to get session ID
func (a AuthorizationSession) GetID() string {
	return a.id
}

// Function to get expiration time in seconds
func (a AuthorizationSession) GetExpirationTimeInSeconds() int {
	return int(a.expirationTime.Unix())
}

// Function to get redirection URI
func (a AuthorizationSession) GetRedirectionURI() string {
	return a.redirectionURI
}

// Function to get state
func (a AuthorizationSession) GetState() string {
	return a.state
}

// Function to compare if session ID is equal
func (a AuthorizationSession) IsExpired() bool {
	return a.expirationTime.After(time.Now())
}

// Function to compare if state is equal
func (a AuthorizationSession) IsStateEqual(state string) bool {
	return a.state == state
}

// Function to create new authorization session
func NewAuthorizationSession(sessionID string, expirationTime time.Time, redirectionURI string, state string) AuthorizationSession {
	return AuthorizationSession{
		id:             sessionID,
		expirationTime: expirationTime,
		redirectionURI: redirectionURI,
		state:          state,
	}
}

// AuthorizationCode is a struct to represent authorization session code
type AuthorizationCode struct {
	code           string
	clientID       string
	redirectionURI string
	expirationTime time.Time
	used           bool
}

// Function to get code
func (a AuthorizationCode) GetCode() string {
	return a.code
}

// Function to get redirection URI
func (a AuthorizationCode) GetRedirectionURI() string {
	return a.redirectionURI
}

// Function to get expiration time in seconds
func (a AuthorizationCode) GetExpirationTimeInSeconds() int {
	return a.expirationTime.Second()
}

// Function to compare if code is equal
func (a AuthorizationCode) IsCodeEqual(code string) bool {
	return a.code == code
}

// Function to compare if code is expired
func (a AuthorizationCode) IsExpired() bool {
	return a.expirationTime.After(time.Now())
}

// Function to compare if redirect URI is equal
func (a AuthorizationCode) IsRedirectionURIEqual(redirectionURI string) bool {
	return a.redirectionURI == redirectionURI
}

func (a AuthorizationCode) GetClientID() string {
	return a.clientID
}

// Function to compare if code is used
func (a AuthorizationCode) IsUsed() bool {
	return a.used
}

// Function to create new authorization session code
func NewAuthorizationCode(code string, redirectionURI string, expirationTime time.Time, clientID string) AuthorizationCode {
	return AuthorizationCode{
		code:           code,
		redirectionURI: redirectionURI,
		expirationTime: expirationTime,
		clientID:       clientID,
		used:           false,
	}
}
