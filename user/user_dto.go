package user

type UserByID struct {
	UserID string
}

type CreateUserRequest struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
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
