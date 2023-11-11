package user

type UserRepository interface {
	CreateUser(user User) (User, error)
	GetUserByID(userID string) (User, error)
	UpdateUser(user User) (User, error)
	GetUserByEmail(email string) (User, error)
}
