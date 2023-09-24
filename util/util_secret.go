package util

import (
	"math/rand"
	"time"
)

const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=[]{}|:;<>,.?/~"

func generatePassword(length int) string {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	password := make([]byte, length)

	for i := 0; i < length; i++ {
		password[i] = chars[rand.Intn(len(chars))]
	}

	return string(password)
}

func NewRandonSecret(length int, isSecretUnique func(string) (bool, error)) string {
	// Verificar si la contraseña es única (aquí puedes agregar tu lógica para verificar la unicidad)
	isUnique := false
	var uniquePassword string
	for !isUnique {
		uniquePassword = generatePassword(length)
		// Comprueba si la contraseña es única, por ejemplo, en una base de datos
		// Si es única, establece isUnique en true y sale del bucle
		// De lo contrario, genera una nueva contraseña y vuelve a verificar
		// hasta que se encuentre una contraseña única.
		isUnique, _ = isSecretUnique(uniquePassword)
	}

	return uniquePassword
}
