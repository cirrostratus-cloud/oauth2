package user

import (
	"errors"

	"github.com/cirrostratus-cloud/oauth2/util"
)

var ErrEmailInvalid = errors.New("email is invalid")

type User struct {
	id             string
	email          string
	password       string
	firstName      string
	lastName       string
	enabled        bool
	changePassword bool
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

func (u *User) ChangePassword(password string) {
	u.password = password
	u.changePassword = false
}

func (u User) IsChangePassword() bool {
	return u.changePassword
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

	return User{id: id, email: email, password: password, enabled: false, changePassword: false}, nil
}
