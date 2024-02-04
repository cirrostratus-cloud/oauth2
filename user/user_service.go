package user

import (
	"errors"

	"github.com/cirrostratus-cloud/common/ulid"
	"github.com/cirrostratus-cloud/oauth2/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var ErrUserIDEmpty = errors.New("user ID is empty")

type CreateUserService struct {
	userRepository    UserRepository
	minPasswordLen    int
	uppercaseRequired bool
	lowercaseRequired bool
	numbersRequired   bool
	specialRequired   bool
}

func NewCreateUserService(userRepository UserRepository, minPasswordLen int, uppercaseRequired bool, lowercaseRequired bool, numberRequired bool, specialRequired bool) CreateUserUseCase {
	return &CreateUserService{
		userRepository:    userRepository,
		minPasswordLen:    minPasswordLen,
		uppercaseRequired: uppercaseRequired,
		lowercaseRequired: lowercaseRequired,
		numbersRequired:   numberRequired,
		specialRequired:   specialRequired,
	}
}

func (service *CreateUserService) NewUser(createUserRequest CreateUserRequest) (CreateUserResponse, error) {
	log.WithFields(
		log.Fields{
			"email": createUserRequest.Email,
		},
	).Info("Creating new user")

	exists, err := service.userRepository.ExistUserByEmail(createUserRequest.Email)

	if err != nil {
		return CreateUserResponse{}, err
	}

	if exists {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).Error("User already exists")
		return CreateUserResponse{}, ErrUserAlreadyExists
	}

	if service.uppercaseRequired && !util.HasUppercase(createUserRequest.Password) {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).Error("Password does not contain uppercase letter")
		return CreateUserResponse{}, ErrPasswordInvalid
	}
	if service.lowercaseRequired && !util.HasLowercase(createUserRequest.Password) {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).Error("Password does not contain lowercase letter")
		return CreateUserResponse{}, ErrPasswordInvalid
	}
	if service.numbersRequired && !util.HasNumber(createUserRequest.Password) {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).Error("Password does not contain number")
		return CreateUserResponse{}, ErrPasswordInvalid
	}
	if service.specialRequired && !util.HasSpecial(createUserRequest.Password) {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).Error("Password does not contain special character")
		return CreateUserResponse{}, ErrPasswordInvalid
	}
	if len(createUserRequest.Password) < service.minPasswordLen {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).Error("Password is too short")
		return CreateUserResponse{}, ErrPasswordInvalid
	}
	password, err := bcrypt.GenerateFromPassword(util.FromStringToByteArray(createUserRequest.Password), bcrypt.DefaultCost)
	if err != nil {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).WithError(err).
			Error("Error generating password")
		return CreateUserResponse{}, err
	}
	user, err := NewUser(ulid.New(), createUserRequest.Email, util.FromByteArrayToString(password))
	if err != nil {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).WithError(err).
			Error("Error creating user")
		return CreateUserResponse{}, err
	}
	user.UpdateUserProfile(createUserRequest.FirstName, createUserRequest.LastName)
	user, err = service.userRepository.CreateUser(user)
	if err != nil {
		log.WithFields(
			log.Fields{
				"email": createUserRequest.Email,
			},
		).WithError(err).
			Error("Error creating user")
		return CreateUserResponse{}, err
	}
	return CreateUserResponse{
		UserID: user.GetID(),
	}, nil
}

type GetUserService struct {
	userRepository UserRepository
}

func NewGetUserService(userRepository UserRepository) GetUserUseCase {
	return &GetUserService{
		userRepository: userRepository,
	}
}

func (service *GetUserService) GetUserByID(userByID UserByID) (GetUserResponse, error) {
	log.WithFields(
		log.Fields{
			"userID": userByID.UserID,
		},
	).Info("Getting user by ID")
	user, err := service.userRepository.GetUserByID(userByID.UserID)
	if err != nil {
		log.WithFields(
			log.Fields{
				"userID": userByID.UserID,
			},
		).WithError(err).
			Error("Error getting user by ID")
		return GetUserResponse{}, err
	}
	return GetUserResponse{
		UserID:    user.GetID(),
		Email:     user.GetEmail(),
		FirstName: user.GetFirstName(),
		LastName:  user.GetLastName(),
		Enabled:   user.IsEnabled(),
	}, nil
}

type DisableUserService struct {
	userRepository UserRepository
}

func NewDisableUserService(userRepository UserRepository) DisableUserUseCase {
	return &DisableUserService{
		userRepository: userRepository,
	}
}

func (service *DisableUserService) DisableUserByID(userByID UserByID) (DisableUserResponse, error) {
	if userByID.UserID == "" {
		log.Error("User ID is empty")
		return DisableUserResponse{}, ErrUserIDEmpty
	}
	log.WithFields(
		log.Fields{
			"userID": userByID.UserID,
		},
	).Info("Disabling user by ID")
	user, err := service.userRepository.GetUserByID(userByID.UserID)
	if err != nil {
		log.WithFields(
			log.Fields{
				"userID": userByID.UserID,
			},
		).WithError(err).
			Error("Error getting user by ID")
		return DisableUserResponse{}, err
	}
	user.DisableUser()
	user, err = service.userRepository.UpdateUser(user)
	if err != nil {
		log.WithFields(
			log.Fields{
				"userID": userByID.UserID,
			},
		).WithError(err).
			Error("Error disabling user by ID")
		return DisableUserResponse{}, err
	}
	return DisableUserResponse{
		UserID: user.GetID(),
	}, nil
}

type EnableUserService struct {
	userRepository UserRepository
}

func NewEnableUserService(userRepository UserRepository) EnableUserUseCase {
	return &EnableUserService{
		userRepository: userRepository,
	}
}

func (e EnableUserService) EnableUserByID(userByID UserByID) (EnableUserResponse, error) {
	user, err := e.userRepository.GetUserByID(userByID.UserID)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": userByID.UserID,
		}).
			WithError(err).
			Error("Error getting user")
		return EnableUserResponse{}, err
	}
	user.EnableUser()
	user, err = e.userRepository.UpdateUser(user)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": user.id,
		}).
			WithError(err).
			Error("Error updating user")
		return EnableUserResponse{}, err
	}
	return EnableUserResponse{
		UserID: user.id,
	}, err
}

type UpdateUserProfileService struct {
	userRepository UserRepository
}

func NewUpdateUserProfileService(userRepository UserRepository) UpdateUserProfileUseCase {
	return &UpdateUserProfileService{
		userRepository: userRepository,
	}
}

func (service *UpdateUserProfileService) UpdateUserProfile(updateUserProfileRequest UpdateUserProfileRequest) (UpdateUserProfileResponse, error) {
	user, err := service.userRepository.GetUserByID(updateUserProfileRequest.UserID)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": updateUserProfileRequest.UserID,
		}).
			WithError(err).
			Error("Error getting user")
		return UpdateUserProfileResponse{}, err
	}
	user.UpdateUserProfile(updateUserProfileRequest.FirstName, updateUserProfileRequest.LastName)
	user, err = service.userRepository.UpdateUser(user)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": updateUserProfileRequest.UserID,
		}).
			WithError(err).
			Error("Error updating user")
		return UpdateUserProfileResponse{}, err
	}
	return UpdateUserProfileResponse{
		UserID:    user.GetID(),
		FirstName: user.GetFirstName(),
		LastName:  user.GetLastName(),
	}, err
}

type AuthenticateUserService struct {
	userRepository UserRepository
}

func NewAuthenticateUserService(userRepository UserRepository) AuthenticateUserUseCase {
	return &AuthenticateUserService{
		userRepository: userRepository,
	}
}

func (service *AuthenticateUserService) AuthenticateUser(authenticateUserRequest AuthenticateUserRequest) (AuthenticateUserResponse, error) {
	user, err := service.userRepository.GetUserByEmail(authenticateUserRequest.Email)
	if err != nil {
		log.WithFields(log.Fields{
			"Email": authenticateUserRequest.Email,
		}).
			WithError(err).
			Error("Error getting user")
		return AuthenticateUserResponse{}, err
	}
	err = bcrypt.CompareHashAndPassword(util.FromStringToByteArray(user.password), util.FromStringToByteArray(authenticateUserRequest.Password))
	if err != nil {
		log.WithFields(log.Fields{
			"Email": authenticateUserRequest.Email,
		}).
			WithError(err).
			Error("Error comparing password")
		return AuthenticateUserResponse{}, err
	}
	return AuthenticateUserResponse{
		UserID: user.GetID(),
	}, nil
}
