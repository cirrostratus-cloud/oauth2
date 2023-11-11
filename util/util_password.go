package util

import "regexp"

const (
	LowercaseRegex = `[a-z]+`
	UppercaseRegex = `[A-Z]+`
	NumberRegex    = `[0-9]+`
	SpecialRegex   = `[!@#$%^&*(),.?":{}|<>]+`
)

func HasLowercase(password string) bool {
	regexp := regexp.MustCompile(LowercaseRegex)
	return regexp.MatchString(password)
}

func HasUppercase(password string) bool {
	regexp := regexp.MustCompile(UppercaseRegex)
	return regexp.MatchString(password)
}

func HasNumber(password string) bool {
	regexp := regexp.MustCompile(NumberRegex)
	return regexp.MatchString(password)
}

func HasSpecial(password string) bool {
	regexp := regexp.MustCompile(SpecialRegex)
	return regexp.MatchString(password)
}
