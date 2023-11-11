package user

import (
	"errors"

	"github.com/cirrostratus-cloud/oauth2/util"
)

var ErrEmailInvalid = errors.New("email is invalid")
var ErrPasswordInvalid = errors.New("password is invalid")

type User struct {
	id        string
	email     string
	password  string
	firstName string
	lastName  string
	enabled   bool
}

func (u User) GetID() string {
	return u.id
}

func (u User) GetFirstName() string {
	return u.firstName
}

func (u User) GetLastName() string {
	return u.lastName
}

func (u User) GetFullName() string {
	return u.firstName + " " + u.lastName
}

func (u User) GetEmail() string {
	return u.email
}

func (u User) GetPassword() string {
	return u.password
}

func (u User) IsEnabled() bool {
	return u.enabled
}

func (u *User) DisableUser() {
	u.enabled = false
}

func (u *User) EnableUser() {
	u.enabled = true
}

func (u *User) UpdateUserProfile(firstName string, lastName string) {
	if firstName != "" {
		u.firstName = firstName
	}
	if lastName != "" {
		u.lastName = lastName
	}
}

func NewUser(id string, email string, password string) (User, error) {
	if !util.ValidateEmail(email) {
		return User{}, ErrEmailInvalid
	}

	if password == "" {
		return User{}, ErrPasswordInvalid
	}

	return User{id: id, email: email, password: password, enabled: true}, nil
}
