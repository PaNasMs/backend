//go:build pam

package auth

import (
	"errors"
	"github.com/msteinert/pam/v2"
)

func Authenticate(user, password string) error {
	t, err := pam.StartFunc("ostojaos", user, func(style pam.Style, message string) (string, error) {
		switch style {
		case pam.PromptEchoOff:
			return password, nil
		case pam.PromptEchoOn:
			return user, nil
		case pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", errors.New("unsupported PAM conversation")
		}
	})
	if err != nil {
		return err
	}
	defer t.End()
	if err = t.Authenticate(0); err != nil {
		return err
	}
	return t.AcctMgmt(0)
}

func ChangePassword(user, current, next string) error {
	if err := Authenticate(user, current); err != nil {
		return err
	}
	t, err := pam.StartFunc("ostojaos", user, func(style pam.Style, message string) (string, error) {
		switch style {
		case pam.PromptEchoOff:
			return next, nil
		case pam.PromptEchoOn:
			return user, nil
		case pam.ErrorMsg, pam.TextInfo:
			return "", nil
		default:
			return "", errors.New("unsupported PAM conversation")
		}
	})
	if err != nil {
		return err
	}
	defer t.End()
	return t.ChangeAuthTok(0)
}
