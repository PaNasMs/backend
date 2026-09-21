//go:build pam

package auth

import (
	"errors"
	"github.com/msteinert/pam/v2"
	"os"
	"strings"
)

var ErrPasswordExpired = errors.New("Password change required")

func Authenticate(user, password string) error {
	t, err := pam.StartFunc("panasms", user, func(style pam.Style, message string) (string, error) {
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
	if err = t.Authenticate(pam.DisallowNullAuthtok); err != nil {
		return err
	}
	err = t.AcctMgmt(pam.DisallowNullAuthtok)
	if errors.Is(err, pam.ErrNewAuthtokReqd) {
		return ErrPasswordExpired
	}
	return err
}

func AccountAllowed(user string) error {
	raw, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return err
	}
	usable := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 2 && fields[0] == user {
			usable = fields[1] != "" && !strings.HasPrefix(fields[1], "!") && !strings.HasPrefix(fields[1], "*")
			break
		}
	}
	if !usable {
		return errors.New("Linux password is locked or unavailable")
	}
	t, err := pam.StartFunc("panasms", user, func(style pam.Style, message string) (string, error) { return "", nil })
	if err != nil {
		return err
	}
	defer t.End()
	return t.AcctMgmt(pam.DisallowNullAuthtok)
}

func ChangePassword(user, current, next string) error {
	if err := Authenticate(user, current); err != nil && !errors.Is(err, ErrPasswordExpired) {
		return errors.New("Incorrect current password or account unavailable")
	}
	var messages []string
	t, err := pam.StartFunc("passwd", user, func(style pam.Style, message string) (string, error) {
		switch style {
		case pam.PromptEchoOff:
			lower := strings.ToLower(message)
			if strings.Contains(lower, "current") || strings.Contains(lower, "old") {
				return current, nil
			}
			return next, nil
		case pam.PromptEchoOn:
			return user, nil
		case pam.ErrorMsg, pam.TextInfo:
			clean := strings.ReplaceAll(strings.ReplaceAll(message, current, "[redacted]"), next, "[redacted]")
			if len(clean) <= 512 && len(messages) < 8 {
				messages = append(messages, clean)
			}
			return "", nil
		default:
			return "", errors.New("unsupported PAM conversation")
		}
	})
	if err != nil {
		return err
	}
	defer t.End()
	if err = t.ChangeAuthTok(0); err != nil {
		if len(messages) > 0 {
			return errors.New("Linux password policy: " + strings.Join(messages, " "))
		}
		return errors.New("Linux rejected the password change: " + err.Error())
	}
	return nil
}
