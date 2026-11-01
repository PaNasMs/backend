package accounts

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"panasms.local/backend/internal/systemops"
)

type homeProcess struct {
	Name string `json:"name"`
	PID  int    `json:"pid"`
}

type homeBlocker struct {
	Title     string        `json:"title"`
	Kind      string        `json:"kind"`
	Unit      string        `json:"unit"`
	User      string        `json:"user"`
	Reason    string        `json:"reason"`
	Processes []homeProcess `json:"processes"`
}

type homeBusy struct{ blockers []homeBlocker }

func (e *homeBusy) Unwrap() error { return reject(e.Error()) }

func (e *homeBusy) Error() string {
	labels := []string{}
	for _, b := range e.blockers {
		labels = append(labels, b.User+": "+b.Title)
	}
	return "Home folders are in use. Close these sessions or applications: " + strings.Join(labels, "; ")
}

func (s *homeService) processApp(ctx context.Context, process, label string, descriptions map[string]string) (string, string, string, error) {
	raw, err := os.ReadFile(filepath.Join(process, "cgroup"))
	if err != nil {
		return "", "", "", err
	}
	unit := ""
	for _, part := range strings.FieldsFunc(string(raw), func(r rune) bool { return r == '/' || r == '\n' }) {
		if strings.HasSuffix(part, ".service") {
			unit = part
		}
	}
	switch {
	case strings.HasPrefix(unit, "panasms-cloud-sync-user-") || unit == "panasms-module-cloud-sync.service":
		return "Cloud Sync", "cloudSync", unit, nil
	case unit == "panasms-module-terminal.service":
		return "Terminal", "terminal", unit, nil
	case unit == "panasms-module-files.service":
		return "Files", "files", unit, nil
	case strings.HasPrefix(label, "sshd"):
		return "SSH session", "ssh", unit, nil
	case (label == "systemd" || label == "(sd-pam)") && strings.HasPrefix(unit, "user@"):
		return "User session", "session", unit, nil
	case unit != "":
		text, ok := descriptions[unit]
		if !ok {
			raw, err := s.run(ctx, []string{"systemctl", "show", unit, "--property=Description", "--value"}, systemops.CommandOptions{Accepted: []int{0, 1}})
			if err != nil {
				return "", "", "", err
			}
			text = strings.TrimSpace(string(raw))
			descriptions[unit] = text
		}
		if text == "" {
			text = unit
		}
		return text, "service", unit, nil
	default:
		return label, "application", "", nil
	}
}

func (s *homeService) blockers(ctx context.Context, source string, users []passwdUser) ([]homeBlocker, error) {
	ids := map[int]string{}
	for _, u := range users {
		ids[u.UID] = u.Name
	}
	all, err := s.users()
	if err != nil {
		return nil, err
	}
	names := map[int]string{}
	for _, u := range all {
		names[u.UID] = u.Name
	}
	entries, err := os.ReadDir(s.proc)
	if err != nil {
		return nil, err
	}
	rows := []homeBlocker{}
	type key struct {
		uid         int
		title, unit string
	}
	indexes := map[key]int{}
	descriptions := map[string]string{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		process := filepath.Join(s.proc, entry.Name())
		info, err := os.Stat(process)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		owner := int(info.Sys().(*syscall.Stat_t).Uid)
		status, err := os.ReadFile(filepath.Join(process, "status"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if exitedProcess(string(status)) {
			continue
		}
		_, used := ids[owner]
		if !used {
			fds, err := os.ReadDir(filepath.Join(process, "fd"))
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			paths := []string{filepath.Join(process, "cwd"), filepath.Join(process, "root")}
			for _, fd := range fds {
				paths = append(paths, filepath.Join(process, "fd", fd.Name()))
			}
			for _, path := range paths {
				value, err := os.Readlink(path)
				if err == nil && childOf(strings.TrimSuffix(value, " (deleted)"), source) {
					used = true
					break
				}
				if err != nil && !os.IsNotExist(err) && !os.IsPermission(err) {
					return nil, err
				}
			}
		}
		if !used {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(process, "comm"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		label := strings.TrimSpace(string(raw))
		title, kind, unit, err := s.processApp(ctx, process, label, descriptions)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		k := key{owner, title, unit}
		index, ok := indexes[k]
		if !ok {
			user := names[owner]
			if user == "" {
				user = strconv.Itoa(owner)
			}
			reason := "openFiles"
			if _, exists := ids[owner]; exists {
				reason = "session"
			}
			index = len(rows)
			indexes[k] = index
			rows = append(rows, homeBlocker{Title: title, Kind: kind, Unit: unit, User: user, Reason: reason, Processes: []homeProcess{}})
		}
		rows[index].Processes = append(rows[index].Processes, homeProcess{Name: label, PID: pid})
	}
	return rows, nil
}
