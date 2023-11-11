package util

import "regexp"

const (
	EmailRegex = `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,4}$`
)

func ValidateEmail(email string) bool {
	regex := regexp.MustCompile(EmailRegex)
	return regex.MatchString(email)
}
