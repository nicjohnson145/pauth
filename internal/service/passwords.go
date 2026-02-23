package service

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordHashingError = errors.New("error hashing password")
)

func HashPassword(pwd string) (string, error) {
	outBytes, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrPasswordHashingError, err)
	}
	return string(outBytes), nil
}

func PasswordsMatch(proposed string, stored string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(proposed)); err != nil {
		return false
	}

	return true
}
