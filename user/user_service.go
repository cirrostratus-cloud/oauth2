package user

import (
	"errors"
	"os"
	"time"

	"github.com/cirrostratus-cloud/common/email"
	"github.com/cirrostratus-cloud/common/event"
	"github.com/cirrostratus-cloud/common/ulid"
	oauth2_event "github.com/cirrostratus-cloud/oauth2/event"
	"github.com/cirrostratus-cloud/oauth2/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

var ErrUserIDEmpty = errors.New("user ID is empty")
var ErrPasswordMismatch = errors.New("passwords do not match")
var ErrPasswordInvalid = errors.New("password is invalid")
var ErrUserIDMismatch = errors.New("user ID mismatch")

type CreateUserService struct {
	userRepository    UserRepository
	eventBus          event.EventBus
	minPasswordLen    int
	uppercaseRequired bool
	lowercaseRequired bool
	numbersRequired   bool
	specialRequired   bool
}

func NewCreateUserService(userRepository UserRepository, minPasswordLen int, uppercaseRequired bool, lowercaseRequired bool, numberRequired bool, specialRequired bool, eventBus event.EventBus) CreateUserUseCase {
	return &CreateUserService{
		userRepository:    userRepository,
		minPasswordLen:    minPasswordLen,
		uppercaseRequired: uppercaseRequired,
		lowercaseRequired: lowercaseRequired,
		numbersRequired:   numberRequired,
		specialRequired:   specialRequired,
		eventBus:          eventBus,
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
	generatedPassword := util.GeneratePassword(service.minPasswordLen, service.uppercaseRequired, service.lowercaseRequired, service.numbersRequired, service.specialRequired)
	password, err := bcrypt.GenerateFromPassword(util.FromStringToByteArray(generatedPassword), bcrypt.DefaultCost)
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
	err = service.eventBus.Publish(oauth2_event.UserCreatedEventName, oauth2_event.UserCreatedEvent{
		UserID: user.GetID(),
	})
	if err != nil {
		log.WithFields(
			log.Fields{
				"userID": user.GetID(),
			},
		).WithError(err).
			Error("Error publishing user created event")
		service.userRepository.DeleteUser(user.GetID())
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

type NotifyUserCreatedService struct {
	userRepository UserRepository
	emailService   email.EmailService
	emailFrom      string
}

func NewNotifyUserCreatedService(userRepository UserRepository, emailService email.EmailService, eventBus event.EventBus, emailFrom string) NotifyUserCreatedUseCase {
	service := &NotifyUserCreatedService{
		userRepository: userRepository,
		emailService:   emailService,
		emailFrom:      emailFrom,
	}
	eventBus.Subscribe(oauth2_event.UserCreatedEventName, func(e event.Event) error {
		userCreatedEvent := e.(oauth2_event.UserCreatedEvent)
		err := service.NotifyUserCreated(NotifyUserCreatedRequest{
			UserID:      userCreatedEvent.UserID,
			RawPassword: userCreatedEvent.RawPassword,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"UserID": userCreatedEvent.UserID,
			}).
				WithError(err).
				Error("Error notifying user created")
		}
		return err

	})
	return service
}

func (service *NotifyUserCreatedService) NotifyUserCreated(notifyUserCreatedRequest NotifyUserCreatedRequest) error {
	user, err := service.userRepository.GetUserByID(notifyUserCreatedRequest.UserID)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyUserCreatedRequest.UserID,
		}).
			WithError(err).
			Error("Error getting user")
		return err
	}
	bytes, err := os.ReadFile("welcome_email.html")
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyUserCreatedRequest.UserID,
		}).
			WithError(err).
			Error("Error reading email html")
		return err
	}
	html, err := email.CreateEmailHtml(map[string]interface{}{
		"Title":    "Welcome to the system",
		"FullName": user.GetFullName(),
		"Password": notifyUserCreatedRequest.RawPassword,
	}, util.FromByteArrayToString(bytes))
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyUserCreatedRequest.UserID,
		}).
			WithError(err).
			Error("Error creating email html")
		return err
	}
	err = service.emailService.SendEmail(
		service.emailFrom,
		user.GetEmail(),
		"Welcome to the system",
		html,
	)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyUserCreatedRequest.UserID,
		}).
			WithError(err).
			Error("Error sending email")
		return err
	}
	return nil
}

type ChangePasswordService struct {
	userRepository          UserRepository
	validatePasswordUseCase ValidatePasswordUseCase
	eventBus                event.EventBus
}

func NewChangePasswordService(userRepository UserRepository, validatePasswordUseCase ValidatePasswordUseCase, eventBus event.EventBus) ChangePasswordUseCase {
	return &ChangePasswordService{
		userRepository:          userRepository,
		validatePasswordUseCase: validatePasswordUseCase,
		eventBus:                eventBus,
	}
}

func (service *ChangePasswordService) ChangePassword(changePasswordRequest ChangePasswordRequest) (ChangePasswordResponse, error) {
	user, err := service.userRepository.GetUserByEmail(changePasswordRequest.Email)
	if err != nil {
		log.WithFields(log.Fields{
			"Email": changePasswordRequest.Email,
		}).
			WithError(err).
			Error("Error getting user")
		return ChangePasswordResponse{}, err
	}
	password := util.FromStringToByteArray(user.GetPassword())
	err = bcrypt.CompareHashAndPassword(password, util.FromStringToByteArray(changePasswordRequest.OldPassword))
	if err != nil {
		log.WithFields(
			log.Fields{
				"email": changePasswordRequest.Email,
			},
		).WithError(err).
			Error("Error comparing password")
		return ChangePasswordResponse{}, err
	}
	if changePasswordRequest.NewPassword != changePasswordRequest.NewPasswordRepeated {
		log.WithFields(
			log.Fields{
				"email": changePasswordRequest.Email,
			},
		).Error("Passwords do not match")
		return ChangePasswordResponse{}, ErrPasswordMismatch
	}
	_, err = service.validatePasswordUseCase.ValidatePassword(ValidatePasswordRequest{
		Email:    changePasswordRequest.Email,
		Password: changePasswordRequest.NewPassword,
	})

	if err != nil {
		log.WithFields(
			log.Fields{
				"email": changePasswordRequest.Email,
			},
		).WithError(err).
			Error("Error validating password")
		return ChangePasswordResponse{}, err
	}

	password, err = bcrypt.GenerateFromPassword(util.FromStringToByteArray(changePasswordRequest.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.WithFields(
			log.Fields{
				"email": changePasswordRequest.Email,
			},
		).WithError(err).
			Error("Error generating password")
		return ChangePasswordResponse{}, err
	}
	oldPassword := user.GetPassword()
	user.ChangePassword(util.FromByteArrayToString(password))
	user, err = service.userRepository.UpdateUser(user)
	if err != nil {
		log.WithFields(
			log.Fields{
				"email": changePasswordRequest.Email,
			},
		).WithError(err).
			Error("Error updating user")
		return ChangePasswordResponse{}, err
	}
	err = service.eventBus.Publish(oauth2_event.UserPasswordChangedEventName, oauth2_event.PasswordChangedEvent{
		UserID: user.GetID(),
	})
	if err != nil {
		log.WithFields(
			log.Fields{
				"userID": user.GetID(),
			},
		).WithError(err).
			Error("Error publishing password changed event")
		user.ChangePassword(oldPassword)
		service.userRepository.UpdateUser(user)
		return ChangePasswordResponse{}, err
	}
	return ChangePasswordResponse{
		UserID: user.GetID(),
	}, nil
}

type ValidatePasswordService struct {
	uppercaseRequired bool
	lowercaseRequired bool
	numbersRequired   bool
	specialRequired   bool
	minPasswordLen    int
}

func NewValidatePasswordService(userRepository UserRepository, uppercaseRequired bool, lowercaseRequired bool, numbersRequired bool, specialRequired bool, minPasswordLen int) ValidatePasswordUseCase {
	return &ValidatePasswordService{
		uppercaseRequired: uppercaseRequired,
		lowercaseRequired: lowercaseRequired,
		numbersRequired:   numbersRequired,
		specialRequired:   specialRequired,
		minPasswordLen:    minPasswordLen,
	}
}

func (service *ValidatePasswordService) ValidatePassword(validatePasswordRequest ValidatePasswordRequest) (ValidatePasswordResponse, error) {
	if service.uppercaseRequired && !util.HasUppercase(validatePasswordRequest.Password) {
		log.WithFields(
			log.Fields{
				"email": validatePasswordRequest.Email,
			},
		).Error("Password does not contain uppercase letter")
		return ValidatePasswordResponse{}, ErrPasswordInvalid
	}
	if service.lowercaseRequired && !util.HasLowercase(validatePasswordRequest.Password) {
		log.WithFields(
			log.Fields{
				"email": validatePasswordRequest.Email,
			},
		).Error("Password does not contain lowercase letter")
		return ValidatePasswordResponse{}, ErrPasswordInvalid
	}
	if service.numbersRequired && !util.HasNumber(validatePasswordRequest.Password) {
		log.WithFields(
			log.Fields{
				"email": validatePasswordRequest.Email,
			},
		).Error("Password does not contain number")
		return ValidatePasswordResponse{}, ErrPasswordInvalid
	}
	if service.specialRequired && !util.HasSpecial(validatePasswordRequest.Password) {
		log.WithFields(
			log.Fields{
				"email": validatePasswordRequest.Email,
			},
		).Error("Password does not contain special character")
		return ValidatePasswordResponse{}, ErrPasswordInvalid
	}
	if len(validatePasswordRequest.Password) < service.minPasswordLen {
		log.WithFields(
			log.Fields{
				"email": validatePasswordRequest.Email,
			},
		).Error("Password is too short")
		return ValidatePasswordResponse{}, ErrPasswordInvalid
	}
	return ValidatePasswordResponse{
		Valid: true,
	}, nil
}

type NotifyPasswordChangedService struct {
	userRepository UserRepository
	emailService   email.EmailService
	emailFrom      string
}

func NewNotifyPasswordChangedService(userRepository UserRepository, emailService email.EmailService, eventBus event.EventBus, emailFrom string) NotifyPasswordChangedUseCase {
	service := &NotifyPasswordChangedService{
		userRepository: userRepository,
		emailService:   emailService,
		emailFrom:      emailFrom,
	}
	eventBus.Subscribe(oauth2_event.UserPasswordChangedEventName, func(e event.Event) error {
		userPasswordChangedEvent := e.(oauth2_event.PasswordChangedEvent)
		err := service.NotifyPasswordChanged(NotifyPasswordChangedRequest{
			UserID: userPasswordChangedEvent.UserID,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"UserID": userPasswordChangedEvent.UserID,
			}).
				WithError(err).
				Error("Error notifying password changed")
		}
		return err
	},
	)
	return service
}

func (service *NotifyPasswordChangedService) NotifyPasswordChanged(notifyPasswordChangedRequest NotifyPasswordChangedRequest) error {
	user, err := service.userRepository.GetUserByID(notifyPasswordChangedRequest.UserID)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyPasswordChangedRequest.UserID,
		}).
			WithError(err).
			Error("Error getting user")
		return err
	}
	bytes, err := os.ReadFile("password_changed_email.html")
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyPasswordChangedRequest.UserID,
		}).
			WithError(err).
			Error("Error reading email html")
		return err
	}
	html, err := email.CreateEmailHtml(map[string]interface{}{
		"Title":    "Password changed",
		"FullName": user.GetFullName(),
	}, util.FromByteArrayToString(bytes))
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyPasswordChangedRequest.UserID,
		}).
			WithError(err).
			Error("Error creating email html")
		return err
	}
	err = service.emailService.SendEmail(
		service.emailFrom,
		user.GetEmail(),
		"Password changed",
		html,
	)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyPasswordChangedRequest.UserID,
		}).
			WithError(err).
			Error("Error sending email")
		return err
	}
	return nil
}

type RequestPasswordRecoveryService struct {
	userRepository  UserRepository
	emailService    email.EmailService
	emailFrom       string
	recoveryURL     string
	maxAgeInSeconds int
	privateKey      []byte
}

func NewRequestPasswordRecoveryService(userRepository UserRepository, emailService email.EmailService, emailFrom string, recoveryURL string, maxAgeInSeconds int, privateKey []byte) RequestPasswordRecoveryUseCase {
	return &RequestPasswordRecoveryService{
		userRepository:  userRepository,
		emailService:    emailService,
		emailFrom:       emailFrom,
		recoveryURL:     recoveryURL,
		maxAgeInSeconds: maxAgeInSeconds,
		privateKey:      privateKey,
	}
}

func (service *RequestPasswordRecoveryService) RequestPasswordRecovery(requestPasswordRecoveryRequest RequestPasswordRecoveryRequest) (RequestPasswordRecoveryResponse, error) {
	user, err := service.userRepository.GetUserByEmail(requestPasswordRecoveryRequest.Email)
	if err != nil {
		log.WithFields(log.Fields{
			"Email": requestPasswordRecoveryRequest.Email,
		}).
			WithError(err).
			Error("Error getting user")
		return RequestPasswordRecoveryResponse{}, err
	}
	token, err := util.GenerateTokenWithExpiration(time.Now().Add(time.Second*time.Duration(service.maxAgeInSeconds)), map[string]interface{}{
		"user_id": user.GetID(),
	}, service.privateKey)
	if err != nil {
		log.WithFields(log.Fields{
			"Email": requestPasswordRecoveryRequest.Email,
		}).
			WithError(err).
			Error("Error generating token")
		return RequestPasswordRecoveryResponse{}, err
	}
	bytes, err := os.ReadFile("password_recovery_email.html")
	if err != nil {
		log.WithFields(log.Fields{
			"Email": requestPasswordRecoveryRequest.Email,
		}).
			WithError(err).
			Error("Error reading email html")
		return RequestPasswordRecoveryResponse{}, err
	}
	html, err := email.CreateEmailHtml(map[string]interface{}{
		"Title":    "Password recovery",
		"FullName": user.GetFullName(),
		"URL":      service.recoveryURL + "?token=" + token,
	}, util.FromByteArrayToString(bytes))
	if err != nil {
		log.WithFields(log.Fields{
			"Email": requestPasswordRecoveryRequest.Email,
		}).
			WithError(err).
			Error("Error creating email html")
		return RequestPasswordRecoveryResponse{}, err
	}
	err = service.emailService.SendEmail(
		service.emailFrom,
		user.GetEmail(),
		"Password recovery",
		html,
	)
	if err != nil {
		log.WithFields(log.Fields{
			"Email": requestPasswordRecoveryRequest.Email,
		}).
			WithError(err).
			Error("Error sending email")
		return RequestPasswordRecoveryResponse{}, err
	}
	return RequestPasswordRecoveryResponse{
		UserID: user.GetID(),
	}, nil
}

type RecoverPasswordService struct {
	userRepository          UserRepository
	eventBus                event.EventBus
	validatePasswordUseCase ValidatePasswordUseCase
	privateKey              []byte
}

func NewRecoverPasswordService(userRepository UserRepository, eventBus event.EventBus, validatePasswordUseCase ValidatePasswordUseCase, privateKey []byte) RecoverPasswordUseCase {
	service := &RecoverPasswordService{
		userRepository:          userRepository,
		eventBus:                eventBus,
		validatePasswordUseCase: validatePasswordUseCase,
		privateKey:              privateKey,
	}
	return service
}

func (service *RecoverPasswordService) RecoverPassword(recoverPasswordRequest RecoverPasswordRequest) (RecoverPasswordResponse, error) {
	claims, err := util.ValidateToken(recoverPasswordRequest.ValidationToken, service.privateKey)
	if err != nil {
		log.WithFields(log.Fields{
			"ValidationToken": recoverPasswordRequest.ValidationToken,
		}).
			WithError(err).
			Error("Error validating token")
		return RecoverPasswordResponse{}, err
	}
	user, err := service.userRepository.GetUserByEmail(recoverPasswordRequest.Email)
	if err != nil {
		log.WithFields(log.Fields{
			"Email": recoverPasswordRequest.Email,
		}).
			WithError(err).
			Error("Error getting user")
		return RecoverPasswordResponse{}, err
	}
	if claims["user_id"] == user.GetID() {
		log.WithFields(log.Fields{
			"UserID": user.GetID(),
		}).
			Error("User ID does not match")
		return RecoverPasswordResponse{}, ErrUserIDMismatch

	}
	oldPassword := user.GetPassword()

	if recoverPasswordRequest.NewPassword != recoverPasswordRequest.NewPasswordRepeated {
		log.WithFields(log.Fields{
			"Email": recoverPasswordRequest.Email,
		}).
			Error("Passwords do not match")
		return RecoverPasswordResponse{}, ErrPasswordMismatch
	}

	_, err = service.validatePasswordUseCase.ValidatePassword(ValidatePasswordRequest{
		Email:    recoverPasswordRequest.Email,
		Password: recoverPasswordRequest.NewPassword,
	})

	if err != nil {
		log.WithFields(log.Fields{
			"Email": recoverPasswordRequest.Email,
		}).
			WithError(err).
			Error("Error changing password")
		user.ChangePassword(oldPassword)
		service.userRepository.UpdateUser(user)
		return RecoverPasswordResponse{}, err
	}
	user.ChangePassword(recoverPasswordRequest.NewPassword)
	user, err = service.userRepository.UpdateUser(user)
	if err != nil {
		log.WithFields(log.Fields{
			"Email": recoverPasswordRequest.Email,
		}).
			WithError(err).
			Error("Error changing password")
		user.ChangePassword(oldPassword)
		service.userRepository.UpdateUser(user)
		return RecoverPasswordResponse{}, err
	}
	err = service.eventBus.Publish(oauth2_event.UserPasswordRecoveredEventName, oauth2_event.UserPasswordRecoveredEvent{
		UserID: user.GetID(),
	})
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": user.GetID(),
		}).
			WithError(err).
			Error("Error publishing password recovered event")
		user.ChangePassword(oldPassword)
		service.userRepository.UpdateUser(user)
		return RecoverPasswordResponse{}, err
	}
	return RecoverPasswordResponse{
		UserID: user.GetID(),
	}, nil
}

type NotifyPasswordRecoveredService struct {
	userRepository UserRepository
	emailService   email.EmailService
	emailFrom      string
}

func NewNotifyPasswordRecoveredService(userRepository UserRepository, emailService email.EmailService, eventBus event.EventBus, emailFrom string) NotifyPasswordRecoveredUseCase {
	service := &NotifyPasswordRecoveredService{
		userRepository: userRepository,
		emailService:   emailService,
		emailFrom:      emailFrom,
	}
	eventBus.Subscribe(oauth2_event.UserPasswordRecoveredEventName, func(e event.Event) error {
		userPasswordRecoveredEvent := e.(oauth2_event.UserPasswordRecoveredEvent)
		err := service.NotifyPasswordRecovered(NotifyPasswordRecoveredRequest{
			UserID: userPasswordRecoveredEvent.UserID,
		})
		if err != nil {
			log.WithFields(log.Fields{
				"UserID": userPasswordRecoveredEvent.UserID,
			}).
				WithError(err).
				Error("Error notifying password recovered")
		}
		return err
	})
	return service
}

func (service *NotifyPasswordRecoveredService) NotifyPasswordRecovered(notifyPasswordRecoveredRequest NotifyPasswordRecoveredRequest) error {
	user, err := service.userRepository.GetUserByID(notifyPasswordRecoveredRequest.UserID)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyPasswordRecoveredRequest.UserID,
		}).
			WithError(err).
			Error("Error getting user")
		return err
	}
	bytes, err := os.ReadFile("password_recovered_email.html")
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyPasswordRecoveredRequest.UserID,
		}).
			WithError(err).
			Error("Error reading email html")
		return err
	}
	html, err := email.CreateEmailHtml(map[string]interface{}{
		"Title":    "Password recovered",
		"FullName": user.GetFullName(),
	}, util.FromByteArrayToString(bytes))
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyPasswordRecoveredRequest.UserID,
		}).
			WithError(err).
			Error("Error creating email html")
		return err
	}
	err = service.emailService.SendEmail(
		service.emailFrom,
		user.GetEmail(),
		"Password recovered",
		html,
	)
	if err != nil {
		log.WithFields(log.Fields{
			"UserID": notifyPasswordRecoveredRequest.UserID,
		}).
			WithError(err).
			Error("Error sending email")
		return err
	}
	return nil
}
