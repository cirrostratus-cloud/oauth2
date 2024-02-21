package util

import (
	"math/rand"
	"regexp"
	"time"
)

const (
	LowercaseRegex = `[a-z]+`
	UppercaseRegex = `[A-Z]+`
	NumberRegex    = `[0-9]+`
	SpecialRegex   = `[!@#$%^&*(),.?":{}|<>]+`
	Characters     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:',.<>?~"
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

func GeneratePassword(minPasswordLen int, uppercaseRequired bool, lowercaseRequired bool, numbersRequired bool, specialRequired bool) string {
	rand.New(rand.NewSource(time.Now().UnixNano()))

	random := func() byte {
		return Characters[rand.Intn(len(Characters))]
	}

	for {
		password := make([]byte, minPasswordLen)
		requirements := 0

		for i := 0; i < minPasswordLen; i++ {
			password[i] = random()
		}

		for _, c := range password {
			switch {
			case numbersRequired && '0' <= c && c <= '9':
				requirements |= 1
			case uppercaseRequired && 'A' <= c && c <= 'Z':
				requirements |= 2
			case lowercaseRequired && 'a' <= c && c <= 'z':
				requirements |= 4
			case specialRequired && c == '!' || c == '@' || c == '#' || c == '$' || c == '%' || c == '^' || c == '&' || c == '*' || c == '(' || c == ')' || c == '-' || c == '_' || c == '=' || c == '+' || c == '[' || c == ']' || c == '{' || c == '}' || c == '|' || c == ';' || c == ':' || c == '\'' || c == ',' || c == '.' || c == '<' || c == '>' || c == '?' || c == '~':
				requirements |= 8
			}
		}

		if requirements == 15 {
			return string(password)
		}
	}
}
