package user

type CreateUserUseCase interface {
	NewUser(user User) (User, error)
}
