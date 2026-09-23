package accounts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"panasms.local/backend/internal/systemops"
	"sort"
	"strconv"
	"strings"
	"time"
)

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func currentUser(target string) (passwdUser, error) {
	users, err := getpwall()
	if err != nil {
		return passwdUser{}, err
	}
	return account(users, target)
}
func memberIDs(target string) (string, error) {
	raw, err := systemops.Command(context.Background(), []string{"id", "-G", "--", target}, systemops.CommandOptions{})
	if err != nil {
		return "", err
	}
	ids := strings.Fields(string(raw))
	sort.Strings(ids)
	return strings.Join(ids, ","), nil
}
func executeAccount(ctx context.Context, action string, p map[string]any, r *systemops.Reporter) error {
	target := stringParam(p, "target")
	run := func(args ...string) error {
		_, err := systemops.Command(ctx, args, systemops.CommandOptions{Operation: true, Reporter: r})
		return err
	}
	password := func() error {
		_, err := systemops.Command(ctx, []string{"chpasswd"}, systemops.CommandOptions{Input: []byte(target + ":" + stringParam(p, "password") + "\n"), Operation: true, Reporter: r})
		return err
	}
	dependency := func(op string) error { _, err := samba(ctx, op, target, stringParam(p, "password")); return err }
	save := func(changes map[string]any, revoke bool) error {
		u, err := currentUser(target)
		if err != nil {
			return err
		}
		return savePolicy(u, changes, revoke)
	}
	primary := stringParam(p, "primaryGroup")
	switch action {
	case "user.create":
		point, err := newHome(p, target)
		if err != nil {
			return err
		}
		args := []string{"useradd", "--create-home", "--home-dir", point, "--shell", "/usr/sbin/nologin"}
		if primary != "" {
			args = append(args, "--gid", primary)
		} else {
			args = append(args, "--user-group")
		}
		args = append(args, "--comment", stringParam(p, "name"), "--", target)
		if err := run(args...); err != nil {
			return err
		}
		if err := os.Chmod(point, 0700); err != nil {
			return err
		}
		if err := save(map[string]any{"panel": false, "ssh": false, "disabled": false, "principal": randomID(), "created": time.Now().UTC().Format(time.RFC3339Nano)}, true); err != nil {
			return err
		}
		if err := password(); err != nil {
			return reject("User created with panel access disabled; Linux rejected the password. Reset the password before enabling access.")
		}
		groups, err := stringList(p, "groups")
		if err != nil {
			return err
		}
		args = []string{"usermod", "--groups", strings.Join(groups, ",")}
		if primary != "" {
			args = append(args, "--gid", primary)
		}
		args = append(args, "--", target)
		if err := run(args...); err != nil {
			return err
		}
		if err := applySSH(ctx); err != nil {
			return err
		}
		return save(map[string]any{"panel": true}, false)
	case "user.edit":
		before, err := memberIDs(target)
		if err != nil {
			return err
		}
		groups, err := stringList(p, "groups")
		if err != nil {
			return err
		}
		args := []string{"usermod", "--comment", stringParam(p, "name"), "--groups", strings.Join(groups, ",")}
		if primary != "" {
			args = append(args, "--gid", primary)
		}
		args = append(args, "--", target)
		if err := run(args...); err != nil {
			return err
		}
		after, err := memberIDs(target)
		if err != nil {
			return err
		}
		if err := save(nil, before != after); err != nil {
			return err
		}
		if before != after {
			return dependency("disconnect")
		}
	case "user.security":
		if err := save(map[string]any{"disabled": p["disabled"], "panel": p["panel"], "ssh": p["ssh"], "expiry": stringParam(p, "expiry")}, true); err != nil {
			return err
		}
		if p["disabled"] == true {
			if err := dependency("disable"); err != nil {
				return err
			}
		}
		end, err := expiry(p["expiry"])
		if err != nil {
			return err
		}
		if p["disabled"] == true {
			end = 1
		}
		args := []string{"chage", "--expiredate", strconv.Itoa(end)}
		for _, field := range []struct{ Key, Flag string }{{"minDays", "--mindays"}, {"maxDays", "--maxdays"}, {"warnDays", "--warndays"}, {"inactiveDays", "--inactive"}} {
			n, err := intParam(p, field.Key, -1)
			if err != nil {
				return err
			}
			args = append(args, field.Flag, strconv.Itoa(n))
		}
		args = append(args, target)
		if err := run(args...); err != nil {
			return err
		}
		st, err := shadow(target)
		if err != nil {
			return err
		}
		if p["forcePasswordChange"] == true {
			if err := run("chage", "--lastday", "0", target); err != nil {
				return err
			}
		} else if st.ForcePasswordChange {
			if err := run("chage", "--lastday", strconv.Itoa(today()), target); err != nil {
				return err
			}
		}
		shell := "/usr/sbin/nologin"
		if p["ssh"] == true {
			shell = stringParam(p, "shell")
		}
		if err := run("usermod", "--shell", shell, "--", target); err != nil {
			return err
		}
		if err := applySSH(ctx); err != nil {
			return err
		}
		if p["disabled"] == true || p["ssh"] == false {
			return terminate(ctx, target, "")
		}
	case "user.identity":
		if err := dependency("disable"); err != nil {
			return err
		}
		u, err := currentUser(target)
		if err != nil {
			return err
		}
		db, err := readPolicy()
		if err != nil {
			return err
		}
		previous := policyEntry(db, u)
		uid, err := intParam(p, "uid", -1)
		if err != nil {
			return err
		}
		if err := run("usermod", "--uid", strconv.Itoa(uid), "--", target); err != nil {
			return err
		}
		return save(previous, true)
	case "user.password":
		if err := password(); err != nil {
			return err
		}
		if err := save(nil, true); err != nil {
			return err
		}
		if p["forcePasswordChange"] == true {
			if err := run("chage", "--lastday", "0", target); err != nil {
				return err
			}
		}
		return dependency("sync-password")
	case "user.home":
		point := stringParam(p, "home")
		if err := run("usermod", "--home", point, "--move-home", "--", target); err != nil {
			return err
		}
		return os.Chmod(point, 0700)
	case "user.delete":
		u, err := currentUser(target)
		if err != nil {
			return err
		}
		if p["deleteHome"] != false {
			if err := run(keysHelper, "--delete-home", target); err != nil {
				return reject("Some home files could not be deleted; the account was preserved")
			}
		}
		if err := savePolicy(u, map[string]any{"disabled": true, "panel": false, "ssh": false}, true); err != nil {
			return err
		}
		if err := dependency("remove"); err != nil {
			return err
		}
		if err := run("userdel", "--", target); err != nil {
			return err
		}
		return applySSH(ctx)
	case "group.edit":
		groups, err := getgrall()
		if err != nil {
			return err
		}
		g, _ := getgrnam(groups, target)
		members, err := stringList(p, "members")
		if err != nil {
			return err
		}
		if err := run("gpasswd", "--members", strings.Join(members, ","), target); err != nil {
			return err
		}
		changed := []string{}
		for _, n := range g.Members {
			if !contains(members, n) {
				changed = append(changed, n)
			}
		}
		for _, n := range members {
			if !contains(g.Members, n) {
				changed = append(changed, n)
			}
		}
		for _, name := range changed {
			if target == "sudo" {
				u, err := currentUser(name)
				if err != nil {
					return err
				}
				if err := savePolicy(u, nil, true); err != nil {
					return err
				}
			}
			if _, err := samba(ctx, "disconnect", name, ""); err != nil {
				return err
			}
		}
	}
	return nil
}
