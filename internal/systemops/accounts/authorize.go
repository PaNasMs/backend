package accounts

import "panasms.local/backend/internal/auth"

func Authorize(username string) (auth.Identity, error) {
	id, err := auth.Lookup(username, nil)
	if err != nil {
		return id, reject("Panel access is disabled or the Linux account is unavailable")
	}
	state, err := shadow(username)
	if err != nil {
		return id, err
	}
	if expired(state) || passwordInactive(state.LastChange, state.MaxDays, state.InactiveDays) {
		return id, reject("Linux account has expired")
	}
	return id, nil
}

func CheckAdmin() error {
	users, err := getpwall()
	if err != nil {
		return err
	}
	groups, err := getgrall()
	if err != nil {
		return err
	}
	for _, u := range users {
		if normal(users, u) == nil && isAdmin(u, groups) {
			return nil
		}
	}
	return reject("Create a regular Linux user in the sudo group before installing PaNasMs")
}
