//go:build !pam

package auth

import "errors"

func Authenticate(user, password string) error {
	return errors.New("PAM support unavailable: rebuild agent with -tags pam")
}

func ChangePassword(user, current, next string) error {
	return errors.New("PAM unavailable in this build")
}
