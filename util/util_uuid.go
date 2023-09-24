package util

import "crypto/rand"

func NewUUIDString() string {
	uuid := make([]byte, 16)
	rand.Read(uuid)
	return string(uuid)
}
