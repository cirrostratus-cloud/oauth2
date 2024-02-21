package util

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

func GenerateTokenWithExpiration(expirationTime time.Time, additionalData map[string]interface{}, privateKey []byte) (string, error) {
	claims := jwt.MapClaims{
		"exp":             expirationTime.Unix(),
		"additional_data": additionalData,
	}
	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := tokenClaims.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func ValidateToken(tokenString string, privateKey []byte) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return privateKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, err
	}
	return claims, nil
}
