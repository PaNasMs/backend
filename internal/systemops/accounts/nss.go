package accounts

import (
	"context"
	"os"
	"panasms.local/backend/internal/systemops"
	"strconv"
	"strings"
)

// passwdUser is one /etc/passwd record. Fields mirror the pwd.struct_passwd the
// Python layer reads.
type passwdUser struct {
	Name  string
	UID   int
	GID   int
	Gecos string
	Dir   string
	Shell string
}

// groupEntry is one /etc/group record, mirroring grp.struct_group.
type groupEntry struct {
	Name    string
	GID     int
	Members []string
}

// getpwall enumerates NSS via getent, matching pwd.getpwall(). Malformed lines (not 7
// colon-separated fields, or a non-numeric uid/gid) are skipped, as getpwall
// would not surface them.
func getpwall() ([]passwdUser, error) {
	raw, err := systemops.Command(context.Background(), []string{"getent", "passwd"}, systemops.CommandOptions{})
	if err != nil {
		return nil, err
	}
	return parsePasswd(raw), nil
}

func localUsers() ([]passwdUser, error) {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}
	return parsePasswd(raw), nil
}

func parsePasswd(raw []byte) []passwdUser {
	var users []passwdUser
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 7 {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		users = append(users, passwdUser{Name: f[0], UID: uid, GID: gid, Gecos: f[4], Dir: f[5], Shell: f[6]})
	}
	return users
}

// getgrall enumerates NSS via getent, matching grp.getgrall(). Empty member fields yield
// an empty member list (Python splits "" to [] for the gr_mem field).
func getgrall() ([]groupEntry, error) {
	raw, err := systemops.Command(context.Background(), []string{"getent", "group"}, systemops.CommandOptions{})
	if err != nil {
		return nil, err
	}
	var groups []groupEntry
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 4 {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		members := []string{}
		if f[3] != "" {
			members = strings.Split(f[3], ",")
		}
		groups = append(groups, groupEntry{Name: f[0], GID: gid, Members: members})
	}
	return groups, nil
}

// getpwnam returns the passwd record for name, or ok=false.
func getpwnam(users []passwdUser, name string) (passwdUser, bool) {
	for _, u := range users {
		if u.Name == name {
			return u, true
		}
	}
	return passwdUser{}, false
}

// getgrnam returns the group record for name, or ok=false.
func getgrnam(groups []groupEntry, name string) (groupEntry, bool) {
	for _, g := range groups {
		if g.Name == name {
			return g, true
		}
	}
	return groupEntry{}, false
}
