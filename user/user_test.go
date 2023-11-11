package user_test

import (
	"errors"
	"testing"

	muser "github.com/cirrostratus-cloud/oauth2/mocks/github.com/cirrostratus-cloud/oauth2/user"
	"github.com/cirrostratus-cloud/oauth2/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateUser(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		GetUserByEmail(mock.AnythingOfType("string")).
		Return(user.User{}, errors.New("user not found")).
		Times(1)
	userRepository.
		On("CreateUser", mock.AnythingOfType("user.User")).
		Return(func(u user.User) (user.User, error) {
			return u, nil
		}).
		Times(1)
	createUserService := user.NewCreateUserService(
		userRepository,
		8,
		true,
		true,
		true,
		true,
	)
	createUserRequest := user.CreateUserRequest{
		Email:     "somemail@mail.com",
		Password:  "S0m3P@ssword",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.Nil(err)
	assert.NotNil(createUserResponse)
}

func TestCreateUserWithInvalidEmail(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		GetUserByEmail(mock.AnythingOfType("string")).
		Return(user.User{}, errors.New("user not found")).
		Times(1)
	createUserService := user.NewCreateUserService(
		userRepository,
		8,
		true,
		true,
		true,
		true,
	)
	createUserRequest := user.CreateUserRequest{
		Email:     "somemail",
		Password:  "S0m3P@ssword",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.NotNil(err)
	assert.Empty(createUserResponse.UserID)
}

func TestCreateUserWithInvalidPassword(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		GetUserByEmail(mock.AnythingOfType("string")).
		Return(user.User{}, errors.New("user not found")).
		Times(1)
	createUserService := user.NewCreateUserService(
		userRepository,
		8,
		true,
		true,
		true,
		true,
	)
	createUserRequest := user.CreateUserRequest{
		Email:     "somemail@mail.com",
		Password:  "somepassword",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.NotNil(err)
	assert.Empty(createUserResponse.UserID)
}

func TestCreateUserWithInvalidPasswordLength(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		GetUserByEmail(mock.AnythingOfType("string")).
		Return(user.User{}, errors.New("user not found")).
		Times(1)
	createUserService := user.NewCreateUserService(
		userRepository,
		8,
		true,
		true,
		true,
		true,
	)
	createUserRequest := user.CreateUserRequest{
		Email:     "somemail@mail.com",
		Password:  "S0m3P@s",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.NotNil(err)
	assert.Empty(createUserResponse.UserID)
}

func TestCreateUserEmailAlreadyExists(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
		Return(func(email string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser("someuserid", email, string(password))
			return u, err
		}).
		Times(1)
	createUserService := user.NewCreateUserService(
		userRepository,
		8,
		true,
		true,
		true,
		true,
	)
	createUserRequest := user.CreateUserRequest{
		Email:     "somemail@mail.com",
		Password:  "S0m3P@ssword",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.NotNil(err)
	assert.Empty(createUserResponse.UserID)
}

func TestGetUserFounded(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	getUserService := user.NewGetUserService(
		userRepository,
	)
	getUserRequest := user.UserByID{
		UserID: "someuserid",
	}
	getUserResponse, err := getUserService.GetUserByID(getUserRequest)
	assert.Nil(err)
	assert.NotEmpty(getUserResponse.Email)
}

func TestGetUserNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	getUserService := user.NewGetUserService(
		userRepository,
	)
	getUserRequest := user.UserByID{
		UserID: "someuserid",
	}
	getUserResponse, err := getUserService.GetUserByID(getUserRequest)
	assert.NotNil(err)
	assert.Empty(getUserResponse.Email)
}

func TestDisableUserOk(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	userRepository.
		On("UpdateUser", mock.AnythingOfType("user.User")).
		Return(func(u user.User) (user.User, error) {
			return u, nil
		}).
		Times(1)

	disableUserService := user.NewDisableUserService(
		userRepository,
	)
	disableUserRequest := user.UserByID{
		UserID: "someuserid",
	}
	user, err := disableUserService.DisableUserByID(disableUserRequest)
	assert.Nil(err)
	assert.NotEmpty(user.UserID)
}

func TestDisableUserNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	disableUserService := user.NewDisableUserService(
		userRepository,
	)
	disableUserRequest := user.UserByID{
		UserID: "someuserid",
	}
	user, err := disableUserService.DisableUserByID(disableUserRequest)
	assert.NotNil(err)
	assert.Empty(user.UserID)
}

func TestEnableUserOk(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	userRepository.
		On("UpdateUser", mock.AnythingOfType("user.User")).
		Return(func(u user.User) (user.User, error) {
			return u, nil
		}).
		Times(1)
	enableUserService := user.NewEnableUserService(userRepository)
	enableUserRequest := user.UserByID{
		UserID: "someuserid",
	}
	user, err := enableUserService.EnableUserByID(enableUserRequest)
	assert.Nil(err)
	assert.NotEmpty(user.UserID)
}

func TestEnableUserNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	enableUserService := user.NewEnableUserService(userRepository)
	enableUserRequest := user.UserByID{
		UserID: "someuserid",
	}
	user, err := enableUserService.EnableUserByID(enableUserRequest)
	assert.NotNil(err)
	assert.Empty(user.UserID)
}

func TestUpdateUserProfileOk(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	userRepository.
		On("UpdateUser", mock.AnythingOfType("user.User")).
		Return(func(u user.User) (user.User, error) {
			return u, nil
		}).
		Times(1)
	updateUserProfileService := user.NewUpdateUserProfileService(userRepository)
	updateUserProfileRequest := user.UpdateUserProfileRequest{
		UserID:    "someuserid",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	user, err := updateUserProfileService.UpdateUserProfile(updateUserProfileRequest)
	assert.Nil(err)
	assert.NotEmpty(user.UserID)
}

func TestUpdateUserProfileNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	updateUserProfileService := user.NewUpdateUserProfileService(userRepository)
	updateUserProfileRequest := user.UpdateUserProfileRequest{
		UserID:    "someuserid",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	user, err := updateUserProfileService.UpdateUserProfile(updateUserProfileRequest)
	assert.NotNil(err)
	assert.Empty(user.UserID)
}
