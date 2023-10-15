package util

import (
	"crypto/rand"
	"encoding/hex"
)

func NewRandomCode(length int) string {
	// Generar un código de autorización aleatorio
	codeBytes := make([]byte, length)
	rand.Read(codeBytes)

	// Convertir el código de autorización a un string
	return hex.EncodeToString(codeBytes)
}
