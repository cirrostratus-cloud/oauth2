package user

type CreateUserUseCase interface {
	NewUser(createUser CreateUserRequest) (CreateUserResponse, error)
}

type GetUserUseCase interface {
	GetUserByID(userByID UserByID) (GetUserResponse, error)
}

type DisableUserUseCase interface {
	DisableUserByID(userByID UserByID) (DisableUserResponse, error)
}

type EnableUserUseCase interface {
	EnableUserByID(userByID UserByID) (EnableUserResponse, error)
}

type UpdateUserProfileUseCase interface {
	UpdateUserProfile(updateUserProfileRequest UpdateUserProfileRequest) (UpdateUserProfileResponse, error)
}

type AuthenticateUserUseCase interface {
	AuthenticateUser(authenticateUserRequest AuthenticateUserRequest) (AuthenticateUserResponse, error)
}
