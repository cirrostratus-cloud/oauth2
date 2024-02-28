package user

type UserByID struct {
	UserID string
}

type CreateUserRequest struct {
	Email            string
	FirstName        string
	LastName         string
	Password         string
	PasswordRepeated string
}

type CreateUserResponse struct {
	UserID string
}

type GetUserResponse struct {
	UserID    string
	Email     string
	FirstName string
	LastName  string
	Enabled   bool
}

type DisableUserResponse struct {
	UserID string
}

type EnableUserResponse struct {
	UserID string
}

type UpdateUserProfileRequest struct {
	UserID    string
	FirstName string
	LastName  string
}

type UpdateUserProfileResponse struct {
	UserID    string
	FirstName string
	LastName  string
}

type AuthenticateUserRequest struct {
	Email    string
	Password string
}

type AuthenticateUserResponse struct {
	UserID    string
	Email     string
	FirstName string
	LastName  string
	Enabled   bool
}

type ChangePasswordRequest struct {
	Email               string
	OldPassword         string
	NewPassword         string
	NewPasswordRepeated string
}

type ChangePasswordResponse struct {
	UserID string
}

type NotifyPasswordChangedRequest struct {
	UserID string
}

type RequestPasswordRecoveryRequest struct {
	Email string
}

type RequestPasswordRecoveryResponse struct {
	UserID string
}

type NotifyPasswordChangedResponse struct {
	UserID string
}

type RecoverPasswordRequest struct {
	Email               string
	NewPassword         string
	NewPasswordRepeated string
	ValidationToken     string
}

type RecoverPasswordResponse struct {
	UserID string
}

type ValidateChangePasswordTokenRequest struct {
	Token string
}

type ValidateChangePasswordTokenResponse struct {
	UserID string
}

type ValidatePasswordRequest struct {
	Email    string
	Password string
}

type ValidatePasswordResponse struct {
	Valid bool
}

type NotifyUserCreatedRequest struct {
	UserID      string
	RawPassword string
}

type NotifyPasswordRecoveredRequest struct {
	UserID string
}

type NotifyPasswordRecoveredResponse struct {
	UserID string
}

type DeleteUserRequest struct {
	UserID string
}

type DeleteUserResponse struct {
	UserID string
}

type NotifyEmailConfirmationRequest struct {
	UserID string
}

type NotifyEmailConfirmationResponse struct {
	UserID string
}

type ConfirmateEmailRequest struct {
	ValidationToken string
}

type ConfirmateEmailResponse struct {
	UserID string
}
