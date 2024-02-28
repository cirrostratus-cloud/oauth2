package user_test

import (
	"errors"
	"testing"
	"time"

	user_event "github.com/cirrostratus-cloud/oauth2/event"
	"github.com/cirrostratus-cloud/oauth2/mocks/github.com/cirrostratus-cloud/common/email"
	mevent "github.com/cirrostratus-cloud/oauth2/mocks/github.com/cirrostratus-cloud/common/event"
	muser "github.com/cirrostratus-cloud/oauth2/mocks/github.com/cirrostratus-cloud/oauth2/user"
	"github.com/cirrostratus-cloud/oauth2/user"
	"github.com/cirrostratus-cloud/oauth2/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateUser(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Publish(user_event.UserCreatedEventName, mock.Anything).
		Return(nil).
		Times(1)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		ExistUserByEmail(mock.AnythingOfType("string")).
		Return(false, nil).
		Times(1)
	userRepository.
		On("CreateUser", mock.AnythingOfType("user.User")).
		Return(func(u user.User) (user.User, error) {
			return u, nil
		}).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	createUserService := user.NewCreateUserService(
		userRepository,
		eventBus,
		validatePasswordService,
	)
	createUserRequest := user.CreateUserRequest{
		Email:            "somemail@mail.com",
		FirstName:        "somefirstname",
		LastName:         "somelastname",
		Password:         "S0m3P@ssword",
		PasswordRepeated: "S0m3P@ssword",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.Nil(err)
	assert.NotNil(createUserResponse)
}

func TestCreateUserWithInvalidEmail(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		ExistUserByEmail(mock.AnythingOfType("string")).
		Return(false, nil).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	createUserService := user.NewCreateUserService(
		userRepository,
		eventBus,
		validatePasswordService,
	)
	createUserRequest := user.CreateUserRequest{
		Email:     "somemail",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.NotNil(err)
	assert.Empty(createUserResponse.UserID)
}

func TestCreateUserEmailAlreadyExists(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		ExistUserByEmail(mock.AnythingOfType("string")).
		Return(true, nil).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	createUserService := user.NewCreateUserService(
		userRepository,
		eventBus,
		validatePasswordService,
	)
	createUserRequest := user.CreateUserRequest{
		Email:     "somemail@mail.com",
		FirstName: "somefirstname",
		LastName:  "somelastname",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.NotNil(err)
	assert.Empty(createUserResponse.UserID)
}

func TestCreateUserPasswordNotValid(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		ExistUserByEmail(mock.AnythingOfType("string")).
		Return(false, nil).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	createUserService := user.NewCreateUserService(
		userRepository,
		eventBus,
		validatePasswordService,
	)
	createUserRequest := user.CreateUserRequest{
		Email:            "somemail@mail.com",
		FirstName:        "somefirstname",
		LastName:         "somelastname",
		Password:         "somepassword",
		PasswordRepeated: "somepassword",
	}
	createUserResponse, err := createUserService.NewUser(createUserRequest)
	assert.NotNil(err)
	assert.Empty(createUserResponse.UserID)
}

func TestCreateUserPasswordNotMatch(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		EXPECT().
		ExistUserByEmail(mock.AnythingOfType("string")).
		Return(false, nil).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	createUserService := user.NewCreateUserService(
		userRepository,
		eventBus,
		validatePasswordService,
	)
	createUserRequest := user.CreateUserRequest{
		Email:            "somemail@mail.com",
		FirstName:        "somefirstname",
		LastName:         "somelastname",
		Password:         "S0m3P@ssword",
		PasswordRepeated: "S0m3P@ssword2",
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

func TestNotifyUserCreatedOk(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserEmailConfirmedEventName, mock.Anything).
		Return(nil).
		Times(1)
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
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(nil).
		Times(1)
	notifyUserCreatedService := user.NewNotifyUserCreatedService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com")
	err := notifyUserCreatedService.NotifyUserCreated(user.NotifyUserCreatedRequest{
		UserID:      "someuserid",
		RawPassword: "S0m3P@ssword",
	})
	assert.Nil(err)
}

func TestNotifyUserCreatedNotFound(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserEmailConfirmedEventName, mock.Anything).
		Return(nil).
		Times(1)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	notifyUserCreatedService := user.NewNotifyUserCreatedService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud")
	err := notifyUserCreatedService.NotifyUserCreated(user.NotifyUserCreatedRequest{
		UserID:      "someuserid",
		RawPassword: "S0m3P@ssword",
	})
	assert.NotNil(err)
}

func TestNotifyUserCreatedEmailError(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserEmailConfirmedEventName, mock.Anything).
		Return(nil).
		Times(1)
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
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(errors.New("error sending email")).
		Times(1)
	notifyUserCreatedService := user.NewNotifyUserCreatedService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com")
	err := notifyUserCreatedService.NotifyUserCreated(user.NotifyUserCreatedRequest{
		UserID:      "someuserid",
		RawPassword: "S0m3P@sword",
	})
	assert.NotNil(err)
}

func TestChangePasswordOk(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
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
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Publish(user_event.UserPasswordChangedEventName, mock.Anything).
		Return(nil).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	changePasswordService := user.NewChangePasswordService(userRepository, validatePasswordService, eventBus)
	changePasswordRequest := user.ChangePasswordRequest{
		OldPassword:         "S0m3P@ssword",
		NewPassword:         "S0m3P@ssword2",
		Email:               "somemail@mail.com",
		NewPasswordRepeated: "S0m3P@ssword2",
	}
	user, err := changePasswordService.ChangePassword(changePasswordRequest)
	assert.Nil(err)
	assert.NotEmpty(user.UserID)
}

func TestChangePasswordInvalidPassword(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}, nil).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	changePasswordService := user.NewChangePasswordService(userRepository, validatePasswordService, nil)
	changePasswordRequest := user.ChangePasswordRequest{
		OldPassword:         "S0m3P@ssword",
		NewPassword:         "S0m3P@ssword2",
		Email:               "somemail@mail.com",
		NewPasswordRepeated: "S0m3P@ssword3",
	}
	user, err := changePasswordService.ChangePassword(changePasswordRequest)
	assert.NotNil(err)
	assert.Empty(user.UserID)
}

func TestChangePasswordUserNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	changePasswordService := user.NewChangePasswordService(userRepository, validatePasswordService, nil)
	changePasswordRequest := user.ChangePasswordRequest{
		OldPassword:         "S0m3P@ssword",
		NewPassword:         "S0m3P@ssword2",
		Email:               "somemail@mail.com",
		NewPasswordRepeated: "S0m3P@ssword2",
	}
	user, err := changePasswordService.ChangePassword(changePasswordRequest)
	assert.NotNil(err)
	assert.Empty(user.UserID)
}

func TestChangePasswordInvalidOldPassword(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	changePasswordService := user.NewChangePasswordService(userRepository, validatePasswordService, eventBus)
	changePasswordRequest := user.ChangePasswordRequest{
		OldPassword:         "S0m3P@ssword1",
		NewPassword:         "S0m3P@ssword",
		Email:               "somemail@mail.com",
		NewPasswordRepeated: "S0m3P@ssword",
	}
	_, err := changePasswordService.ChangePassword(changePasswordRequest)
	assert.NotNil(err)
}

func TestRequestRecoverPasswordOk(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(nil).
		Times(1)
	requestPasswordRecovery := user.NewRequestPasswordRecoveryService(userRepository, emailService, "cirrostratus-cloud@cloud.com", "https://example.com/reset", 3600, util.FromStringToByteArray("somekey"))
	_, err := requestPasswordRecovery.RequestPasswordRecovery(user.RequestPasswordRecoveryRequest{
		Email: "somemail@mail.com",
	})
	assert.Nil(err)
}

func TestRequestRecoverPasswordUserNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	requestPasswordRecovery := user.NewRequestPasswordRecoveryService(userRepository, emailService, "cirrostratus-cloud@cloud.com", "https://example.com/reset", 3600, util.FromStringToByteArray("somekey"))
	_, err := requestPasswordRecovery.RequestPasswordRecovery(user.RequestPasswordRecoveryRequest{
		Email: "somemail@mail.com",
	})
	assert.NotNil(err)
}

func TestRequestRecoverPasswordEmailError(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("S0m3P@ssword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(errors.New("error sending email")).
		Times(1)
	requestPasswordRecovery := user.NewRequestPasswordRecoveryService(userRepository, emailService, "cirrostratus-cloud@cloud.com", "https://example.com/reset", 3600, util.FromStringToByteArray("somekey"))
	_, err := requestPasswordRecovery.RequestPasswordRecovery(user.RequestPasswordRecoveryRequest{
		Email: "somemail@mail.com",
	})
	assert.NotNil(err)
}

func TestRecoverPasswordInvalidToken(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	eventBus := mevent.NewMockEventBus(t)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	recoverPasswordService := user.NewRecoverPasswordService(userRepository, eventBus, validatePasswordService, util.FromStringToByteArray("somekey"))
	_, err := recoverPasswordService.RecoverPassword(user.RecoverPasswordRequest{
		Email:               "somemail@mail.com",
		NewPassword:         "S0m3P@ssword",
		NewPasswordRepeated: "S0m3P@ssword",
		ValidationToken:     "invalidtoken",
	})
	assert.NotNil(err)
}

func TestRecoverPasswordUserNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	token, err := util.GenerateTokenWithExpiration(time.Now().Add(time.Hour*24), map[string]interface{}{"user_id": ""}, util.FromStringToByteArray("somekey"))
	assert.Nil(err)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	recoverPasswordService := user.NewRecoverPasswordService(userRepository, eventBus, validatePasswordService, util.FromStringToByteArray("somekey"))
	_, err = recoverPasswordService.RecoverPassword(user.RecoverPasswordRequest{
		Email:               "somemail@mail.com",
		NewPassword:         "S0m3P@ssword",
		NewPasswordRepeated: "S0m3P@ssword",
		ValidationToken:     token,
	})
	assert.NotNil(err)
}

func TestRecoverPasswordInvalidPassword(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
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
	eventBus := mevent.NewMockEventBus(t)
	token, err := util.GenerateTokenWithExpiration(time.Now().Add(time.Hour*24), map[string]interface{}{"user_id": ""}, util.FromStringToByteArray("somekey"))
	assert.Nil(err)
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	recoverPasswordService := user.NewRecoverPasswordService(userRepository, eventBus, validatePasswordService, util.FromStringToByteArray("somekey"))
	_, err = recoverPasswordService.RecoverPassword(user.RecoverPasswordRequest{
		Email:               "somemail@mail.com",
		NewPassword:         "somepassword",
		NewPasswordRepeated: "somepassword",
		ValidationToken:     token,
	})
	assert.NotNil(err)
}

func TestRecoverPasswordOk(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Publish(user_event.UserPasswordRecoveredEventName, mock.Anything).
		Return(nil).
		Times(1)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByEmail", mock.AnythingOfType("string")).
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
	validatePasswordService := user.NewValidatePasswordService(userRepository, true, true, true, true, 8)
	recoverPasswordService := user.NewRecoverPasswordService(userRepository, eventBus, validatePasswordService, util.FromStringToByteArray("somekey"))
	token, err := util.GenerateTokenWithExpiration(time.Now().Add(time.Hour*24), map[string]interface{}{"user_id": ""}, util.FromStringToByteArray("somekey"))
	assert.Nil(err)
	_, err = recoverPasswordService.RecoverPassword(user.RecoverPasswordRequest{
		Email:               "somemail@mail.com",
		NewPassword:         "S0m3P@ssword",
		NewPasswordRepeated: "S0m3P@ssword",
		ValidationToken:     token,
	})
	assert.Nil(err)
}

func TestNotifyPasswordRecoveredOk(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserPasswordRecoveredEventName, mock.Anything).
		Return(nil).
		Times(1)
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
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(nil).
		Times(1)
	notifyPasswordRecoveredService := user.NewNotifyPasswordRecoveredService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com")
	err := notifyPasswordRecoveredService.NotifyPasswordRecovered(user.NotifyPasswordRecoveredRequest{
		UserID: "someuserid",
	})
	assert.Nil(err)
}

func TestNotifyPasswordRecoveredUserNotFound(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserPasswordRecoveredEventName, mock.Anything).
		Return(nil).
		Times(1)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	notifyPasswordRecoveredService := user.NewNotifyPasswordRecoveredService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com")
	err := notifyPasswordRecoveredService.NotifyPasswordRecovered(user.NotifyPasswordRecoveredRequest{
		UserID: "someuserid",
	})
	assert.NotNil(err)
}

func TestNotifyPasswordRecoveredEmailError(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserPasswordRecoveredEventName, mock.Anything).
		Return(nil).
		Times(1)
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
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(errors.New("error sending email")).
		Times(1)
	notifyPasswordRecoveredService := user.NewNotifyPasswordRecoveredService(userRepository, emailService, eventBus, "cirrostatus-cloud@cloud.com")
	err := notifyPasswordRecoveredService.NotifyPasswordRecovered(user.NotifyPasswordRecoveredRequest{
		UserID: "someuserid",
	})
	assert.NotNil(err)
}

func TestNotifyPasswordChangedOk(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserPasswordChangedEventName, mock.Anything).
		Return(nil).
		Times(1)
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

	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(nil).
		Times(1)
	notifyPasswordChangedService := user.NewNotifyPasswordChangedService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com")
	err := notifyPasswordChangedService.NotifyPasswordChanged(user.NotifyPasswordChangedRequest{
		UserID: "someuserid",
	})
	assert.Nil(err)
}

func TestNotifyPasswordChangedUserNotFound(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserPasswordChangedEventName, mock.Anything).
		Return(nil).
		Times(1)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	notifyPasswordChangedService := user.NewNotifyPasswordChangedService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com")
	err := notifyPasswordChangedService.NotifyPasswordChanged(user.NotifyPasswordChangedRequest{
		UserID: "someuserid",
	})
	assert.NotNil(err)
}

func TestNotifyPasswordChangedEmailError(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserPasswordChangedEventName, mock.Anything).
		Return(nil).
		Times(1)
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
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(errors.New("error sending email")).
		Times(1)
	notifyPasswordChangedService := user.NewNotifyPasswordChangedService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com")
	err := notifyPasswordChangedService.NotifyPasswordChanged(user.NotifyPasswordChangedRequest{
		UserID: "someuserid",
	})
	assert.NotNil(err)
}

func TestDeleteUserOk(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("DeleteUser", mock.AnythingOfType("string")).
		Return(func(id string) error {
			return nil
		}).
		Times(1)
	deleteUserService := user.NewDeleteUserService(userRepository)
	_, err := deleteUserService.DeleteUser(user.DeleteUserRequest{
		UserID: "someuserid",
	})
	assert.Nil(err)
}

func TestDeleteUserNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("DeleteUser", mock.AnythingOfType("string")).
		Return(func(id string) error {
			return errors.New("user not found")
		}).
		Times(1)
	deleteUserService := user.NewDeleteUserService(userRepository)
	_, err := deleteUserService.DeleteUser(user.DeleteUserRequest{
		UserID: "someuserid",
	})
	assert.NotNil(err)
}

func TestNotifyEmailConfirmationOk(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserCreatedEventName, mock.Anything).
		Return(nil).
		Times(1)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("somepassword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(nil).
		Times(1)
	notifyEmailConfirmationService := user.NewNotifyEmailConfirmationService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com", "https://example.com/confirm", util.FromStringToByteArray("somekey"), 3600)
	err := notifyEmailConfirmationService.NotifyEmailConfirmation(user.NotifyEmailConfirmationRequest{
		UserID: "someuserid",
	})
	assert.Nil(err)
}

func TestNotifyEmailConfirmationUserNotFound(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserCreatedEventName, mock.Anything).
		Return(nil).
		Times(1)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	notifyEmailConfirmationService := user.NewNotifyEmailConfirmationService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com", "https://example.com/confirm", util.FromStringToByteArray("somekey"), 3600)
	err := notifyEmailConfirmationService.NotifyEmailConfirmation(user.NotifyEmailConfirmationRequest{
		UserID: "someuserid",
	})
	assert.NotNil(err)
}

func TestNotifyEmailConfirmationEmailError(t *testing.T) {
	assert := assert.New(t)
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Subscribe(user_event.UserCreatedEventName, mock.Anything).
		Return(nil).
		Times(1)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("somepassword"), bcrypt.DefaultCost)
			if err != nil {
				return user.User{}, err
			}
			u, err := user.NewUser(id, "somemail@mail.com", string(password))
			return u, err
		}).
		Times(1)
	emailService := email.NewMockEmailService(t)
	emailService.
		EXPECT().
		SendEmail(mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("string")).
		Return(errors.New("error sending email")).
		Times(1)
	notifyEmailConfirmationService := user.NewNotifyEmailConfirmationService(userRepository, emailService, eventBus, "cirrostratus-cloud@cloud.com", "https://example.com/confirm", util.FromStringToByteArray("somekey"), 3600)
	err := notifyEmailConfirmationService.NotifyEmailConfirmation(user.NotifyEmailConfirmationRequest{
		UserID: "someuserid",
	})
	assert.NotNil(err)
}

func TestConfirmateEmailOk(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			password, err := bcrypt.GenerateFromPassword([]byte("somepassword"), bcrypt.DefaultCost)
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
	eventBus := mevent.NewMockEventBus(t)
	eventBus.
		EXPECT().
		Publish(user_event.UserEmailConfirmedEventName, mock.Anything).
		Return(nil).
		Times(1)
	token, err := util.GenerateTokenWithExpiration(time.Now().Add(time.Hour*24), map[string]interface{}{"user_id": "someid"}, util.FromStringToByteArray("somekey"))
	assert.Nil(err)
	confirmateEmailService := user.NewConfirmateEmailService(userRepository, eventBus, util.FromStringToByteArray("somekey"))
	_, err = confirmateEmailService.ConfirmateEmail(user.ConfirmateEmailRequest{
		ValidationToken: token,
	})
	assert.Nil(err)
}

func TestConfirmateEmailInvalidToken(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	eventBus := mevent.NewMockEventBus(t)
	confirmateEmailService := user.NewConfirmateEmailService(userRepository, eventBus, util.FromStringToByteArray("somekey"))
	_, err := confirmateEmailService.ConfirmateEmail(user.ConfirmateEmailRequest{
		ValidationToken: "invalidtoken",
	})
	assert.NotNil(err)
}

func TestConfirmateEmailUserNotFound(t *testing.T) {
	assert := assert.New(t)
	userRepository := muser.NewMockUserRepository(t)
	userRepository.
		On("GetUserByID", mock.AnythingOfType("string")).
		Return(func(id string) (user.User, error) {
			return user.User{}, errors.New("user not found")
		}).
		Times(1)
	eventBus := mevent.NewMockEventBus(t)
	token, err := util.GenerateTokenWithExpiration(time.Now().Add(time.Hour*24), map[string]interface{}{"user_id": "someid"}, util.FromStringToByteArray("somekey"))
	assert.Nil(err)
	confirmateEmailService := user.NewConfirmateEmailService(userRepository, eventBus, util.FromStringToByteArray("somekey"))
	_, err = confirmateEmailService.ConfirmateEmail(user.ConfirmateEmailRequest{
		ValidationToken: token,
	})
	assert.NotNil(err)
}
