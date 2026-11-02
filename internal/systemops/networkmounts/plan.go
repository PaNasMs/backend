package networkmounts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/folders"
)

func reject(message string) error               { return &systemops.Rejected{Message: message} }
func param(p map[string]any, key string) string { s, _ := p[key].(string); return s }
func Key(point string) string {
	sum := sha256.Sum256([]byte(point))
	return hex.EncodeToString(sum[:])[:24]
}
func marker(point string) string { return "# panasms-network-" + Key(point) }
func IsAction(action string) bool {
	return action == "nfs.mount" || action == "nfs.unmount" || action == "smb.mount" || action == "smb.unmount"
}
func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, strings.TrimRight(root, "/")+"/")
}

type service struct {
	attach             func(string, *os.File, func(uint64) error) (uint64, error)
	unmount            func(string, folders.LiveMount) error
	root               string
	proc               string
	owner              int
	write              func(string, string, os.FileMode) error
	fstab, credentials string
	mounts             func() ([]folders.LiveMount, error)
	lookup             func(string) (*user.User, error)
	path               func(string) error
	run                func(context.Context, []string, systemops.CommandOptions) ([]byte, error)
}

func defaultService() *service {
	return &service{proc: "/proc", attach: attachStaged, unmount: unmountPinned, root: "/var/lib/panasms-agent/network-mounts", owner: 0, write: systemops.AtomicWrite, fstab: "/etc/fstab", credentials: "/etc/panasms/network-credentials", mounts: folders.ReadMounts, lookup: user.Lookup, path: folders.MountPath, run: systemops.Command}
}
func safePath(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		st, err := os.Lstat(current)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return reject("Links in the mount path are not allowed")
		}
		if current == "/" {
			return nil
		}
	}
}
func configuredRows(text string) [][]string {
	rows := [][]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			rows = append(rows, strings.Fields(line))
		}
	}
	return rows
}

var nfsSource = regexp.MustCompile(`^[a-zA-Z0-9.-]+:/[^\s\x00\\#]*$`)
var smbSource = regexp.MustCompile(`^//[a-zA-Z0-9.-]+/[^/\s\x00\\#]+$`)

func Plan(ctx context.Context, action string, p map[string]any, name string) (json.RawMessage, error) {
	return defaultService().plan(ctx, action, p, name)
}

type preparedPlan struct {
	identity    []string
	raw         json.RawMessage
	conf, point string
	mounts      []folders.LiveMount
	record      *transaction
	witness     pathWitness
}

func (s *service) plan(ctx context.Context, action string, p map[string]any, name string) (json.RawMessage, error) {
	prepared, err := s.prepare(ctx, action, p, name)
	if err != nil {
		return nil, err
	}
	return prepared.raw, nil
}
func (s *service) prepare(ctx context.Context, action string, p map[string]any, name string) (*preparedPlan, error) {
	if !IsAction(action) {
		return nil, reject("Unknown operation")
	}
	mounting := strings.HasSuffix(action, ".mount")
	point := param(p, "target")
	if mounting {
		point = param(p, "point")
	}
	if err := s.path(point); err != nil {
		return nil, err
	}
	if err := safePath(point); err != nil {
		return nil, err
	}
	if strings.ContainsAny(point, "\\,#") || strings.ContainsFunc(point, unicode.IsSpace) {
		return nil, reject("Choose a mount point without spaces, commas or backslashes")
	}
	if err := safePath(s.fstab); err != nil {
		return nil, err
	}
	conf, err := os.ReadFile(s.fstab)
	if err != nil {
		return nil, err
	}
	mounts, err := s.mounts()
	if err != nil {
		return nil, err
	}
	matches := []folders.LiveMount{}
	for _, m := range mounts {
		if m.Target == point {
			matches = append(matches, m)
		}
		if m.Target != point && within(m.Target, point) {
			return nil, reject("The folder contains mounted volumes; unmount them first")
		}
	}
	record, err := s.load(point)
	if err != nil {
		return nil, err
	}
	target := param(p, "target")
	details := []string{}
	identity := []string{}
	if mounting {
		if record != nil {
			return nil, reject("A network mount operation already exists; unmount the share before trying again")
		}
		valid := nfsSource.MatchString(target)
		if action == "smb.mount" {
			valid = smbSource.MatchString(target)
		}
		if !valid {
			return nil, reject("Specify server:/path for NFS or //server/share for SMB")
		}
		if len(matches) > 0 {
			return nil, reject("This mount point is already mounted")
		}
		if info, err := os.Stat(point); err == nil {
			if !info.IsDir() {
				return nil, reject("The mount point must be an empty directory")
			}
			entries, e := os.ReadDir(point)
			if e != nil {
				return nil, e
			}
			if len(entries) > 0 {
				return nil, reject("The mount point must be an empty directory")
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		for _, row := range configuredRows(string(conf)) {
			if len(row) > 1 && folders.UnescapeMount(row[1]) == point {
				return nil, reject("The mount point is already configured in fstab")
			}
		}
		for _, field := range []string{"automount", "readOnly"} {
			if value, exists := p[field]; exists {
				if _, ok := value.(bool); !ok {
					return nil, reject("Invalid mount mode")
				}
			}
		}
		if action == "smb.mount" {
			for _, field := range []string{"username", "password", "domain"} {
				if value, exists := p[field]; exists {
					str, ok := value.(string)
					if !ok || len(str) > 4096 || strings.ContainsAny(str, "\r\n\x00") {
						return nil, reject("Invalid SMB credentials")
					}
				}
			}
			if param(p, "username") == "" || param(p, "password") == "" {
				return nil, reject("Specify SMB username and password")
			}
			account, err := s.lookup(name)
			if err != nil {
				return nil, err
			}
			identity = []string{account.Uid, account.Gid}
			if _, err = os.Lstat(filepath.Join(s.credentials, Key(point))); err == nil {
				return nil, reject("Credentials are already stored for this mount point; choose another")
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
		access := "Read and write"
		if p["readOnly"] == true {
			access = "Read-only"
		}
		duration := "Until unmounted or restarted"
		if p["automount"] == true {
			duration = "Mount at startup"
		}
		details = []string{target, point, access, duration}

	} else {
		row, err := ownedEntry(string(conf), point)
		if err != nil {
			return nil, err
		}
		validType := func(fs string) bool {
			if action == "nfs.unmount" {
				return fs == "nfs" || fs == "nfs4"
			}
			return fs == "cifs"
		}
		source := ""
		if len(matches) > 1 {
			return nil, reject("Network mount not found")
		}
		if len(matches) == 1 {
			m := matches[0]
			if !validType(m.FSType) {
				return nil, reject("Network mount not found")
			}
			source = m.Source
			if record != nil && (record.Source != m.Source || !validType(record.FSType)) {
				return nil, reject("The mount changed; review a new operation plan")
			}
			busy, err := s.run(ctx, []string{"fuser", "-m", point}, systemops.CommandOptions{Accepted: []int{0, 1}})
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(string(busy)) != "" {
				return nil, reject("Folder is in use by processes (PID: " + s.busyDescription(string(busy)) + "). Finish file transfers or close programs using the folder.")
			}
		} else if record != nil && validType(record.FSType) {
			source = record.Source
		} else if row != nil && validType(row[2]) {
			source = row[0]
		} else {
			return nil, reject("Network mount not found")
		}
		if row != nil && (!validType(row[2]) || row[0] != source) {
			return nil, reject("Network mount configuration changed; review recovery before continuing")
		}
		details = []string{source, point, "Unmount the share and remove automatic mounting if configured by the panel"}

	}
	witness, file, err := closestDirectory(point)
	if err != nil {
		return nil, err
	}
	file.Close()
	raw, err := json.Marshal([]any{p, []any{string(conf), mounts, name, identity, record, witness}})
	if err != nil {
		return nil, err
	}
	var state []any
	if err = systemops.Decode(raw, &state); err != nil {
		return nil, err
	}
	fp, err := systemops.Fingerprint(action, state[0].(map[string]any), state[1])
	if err != nil {
		return nil, fmt.Errorf("mount plan: %w", err)
	}
	raw, err = json.Marshal(map[string]any{"target": target, "details": details, "confirmation": target, "fingerprint": fp})
	if err != nil {
		return nil, err
	}
	return &preparedPlan{identity: identity, raw: raw, conf: string(conf), point: point, mounts: mounts, record: record, witness: witness}, nil
}

func ownedEntry(text, point string) ([]string, error) {
	var result []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasSuffix(strings.TrimSpace(line), marker(point)) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 || folders.UnescapeMount(fields[1]) != point || result != nil {
			return nil, reject("Network mount configuration changed; review recovery before continuing")
		}
		result = fields
	}
	return result, nil
}
