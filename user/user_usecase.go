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

type NotifyUserCreatedUseCase interface {
	NotifyUserCreated(notifyUserCreated NotifyUserCreatedRequest) error
}

type ChangePasswordUseCase interface {
	ChangePassword(changePasswordRequest ChangePasswordRequest) (ChangePasswordResponse, error)
}

type NotifyPasswordChangedUseCase interface {
	NotifyPasswordChanged(notifyPasswordChanged NotifyPasswordChangedRequest) error
}

type NotifyPasswordRecoveredUseCase interface {
	NotifyPasswordRecovered(notifyPasswordRecovered NotifyPasswordRecoveredRequest) error
}
type RecoverPasswordUseCase interface {
	RecoverPassword(recoverPasswordRequest RecoverPasswordRequest) (RecoverPasswordResponse, error)
}

type ValidatePasswordUseCase interface {
	ValidatePassword(validatePasswordRequest ValidatePasswordRequest) (ValidatePasswordResponse, error)
}

type RequestPasswordRecoveryUseCase interface {
	RequestPasswordRecovery(requestPasswordRecoveryRequest RequestPasswordRecoveryRequest) (RequestPasswordRecoveryResponse, error)
}

type DeleteUserUseCase interface {
	DeleteUser(deleteUserRequest DeleteUserRequest) (DeleteUserResponse, error)
}

type NotifyEmailConfirmationUseCase interface {
	NotifyEmailConfirmation(notifyEmailConfirmation NotifyEmailConfirmationRequest) error
}

type ConfirmateEmailUseCase interface {
	ConfirmateEmail(confirmateEmailRequest ConfirmateEmailRequest) (ConfirmateEmailResponse, error)
}
