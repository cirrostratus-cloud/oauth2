package user

import "errors"

var ErrUserNotFound = errors.New("user not found")
var ErrUserAlreadyExists = errors.New("user already exists")
var ErrUserEmailNotFound = errors.New("user email not found")

type UserRepository interface {
	CreateUser(user User) (User, error)
	GetUserByID(userID string) (User, error)
	UpdateUser(user User) (User, error)
	GetUserByEmail(email string) (User, error)
	ExistUserByEmail(email string) (bool, error)
	DeleteUser(userID string) error
}
