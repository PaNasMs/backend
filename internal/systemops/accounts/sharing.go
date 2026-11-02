package accounts

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const sharingHeader = "# Managed by PaNasMs. Edit using Shared folders.\n"
const sharingDrift = "Sharing configuration was edited outside the panel. Restore the managed configuration before continuing."
const sharingPending = "Interrupted sharing update requires recovery"

type sharedFolder struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	SMB        bool     `json:"smb"`
	NFS        bool     `json:"nfs"`
	ReadOnly   bool     `json:"readOnly"`
	Clients    []string `json:"clients"`
	Readers    []string `json:"readers"`
	Writers    []string `json:"writers"`
	Volume     string   `json:"volume"`
	Mountpoint string   `json:"mountpoint"`
}
type sharedAccount struct {
	UID              *int   `json:"uid,omitempty"`
	Enabled          bool   `json:"enabled"`
	Status           string `json:"status,omitempty"`
	PasswordRevision string `json:"passwordRevision,omitempty"`
}
type sharingState struct {
	Shares   []sharedFolder            `json:"shares"`
	Accounts map[string]*sharedAccount `json:"accounts"`
}
type sharingCredentials struct {
	UID      int
	Disabled bool
	Shadow   ShadowState
	Revision string
}
type sharingService struct {
	locate                                                                                   func(context.Context, string) (sharingMount, error)
	identity                                                                                 func(string) ([]uint64, error)
	state, smb, exports, legacy, journal, lock, mainConfig, installer, vendor, passwd, group string
	run                                                                                      func(context.Context, []string, systemops.CommandOptions) ([]byte, error)
	write                                                                                    func(string, string, os.FileMode) error
	tool                                                                                     func(string) bool
	user                                                                                     func(string) (passwdUser, error)
	normal                                                                                   func(passwdUser) error
	groups                                                                                   func() ([]groupEntry, error)
	revision                                                                                 func(string) (string, error)
	credentials                                                                              func(string) (sharingCredentials, error)
}

func defaultSharing() *sharingService {
	service := &sharingService{
		state: "/etc/panasms/sharing.json", smb: "/etc/samba/panasms-shares.conf", exports: "/etc/exports.d/panasms-shares.exports", legacy: "/etc/exports.d/panasms.exports",
		journal: "/var/lib/panasms-agent/sharing-transaction.json", lock: "/var/lib/panasms-agent/sharing.lock", mainConfig: "/etc/samba/smb.conf", installer: "/var/lib/panasms-installer", vendor: "/usr/share/samba/smb.conf", passwd: "/etc/passwd", group: "/etc/group",
		run: systemops.Command, write: systemops.AtomicWrite, tool: func(name string) bool { _, err := exec.LookPath(name); return err == nil },
		user: func(name string) (passwdUser, error) {
			users, err := getpwall()
			if err != nil {
				return passwdUser{}, err
			}
			u, ok := getpwnam(users, name)
			if !ok {
				return u, reject("User not found")
			}
			return u, nil
		},
		normal: func(u passwdUser) error { return normal(nil, u) }, groups: getgrall, revision: sharingPasswordRevision, credentials: readSharingCredentials,
	}
	service.locate = service.readLocation
	service.identity = homeIdentity
	return service
}
func sharingText(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(raw), err
}
func sharingExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
func shareName(name string) bool {
	if name == "" || utf8.RuneCountInString(name) > 64 || !utf8.ValidString(name) {
		return false
	}
	for i, r := range name {
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsNumber(r) && (i == 0 || r != '.' && r != '-') {
			return false
		}
	}
	return !slices.Contains([]string{"global", "homes", "printers", "print$", "ipc$"}, strings.ToLower(name))
}
func sharePathShape(path string) error {
	if _, err := systemops.CleanPath(path); err != nil {
		return err
	}
	if !(strings.HasPrefix(path, "/srv/") || strings.HasPrefix(path, "/mnt/") || strings.HasPrefix(path, "/media/")) {
		return reject("The mount point must be under /srv, /mnt or /media")
	}
	if strings.ContainsAny(path, " \t\\\"") {
		return reject("The share path must not contain spaces or quotation marks")
	}
	if strings.ContainsAny(path, "%#;[]\r\n") {
		return reject("Share path contains unsupported configuration characters")
	}
	return nil
}
func sharingMountPath(path string) bool {
	_, err := systemops.CleanPath(path)
	return err == nil && path != "/"
}
func (s *sharingService) read() (sharingState, error) {
	st := sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}}
	raw, err := os.ReadFile(s.state)
	if os.IsNotExist(err) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err = systemops.Decode(raw, &st); err != nil {
		return st, err
	}
	return st, validateSharingState(st)
}
func validateSharingState(st sharingState) error {
	if st.Shares == nil || st.Accounts == nil {
		return reject("Invalid sharing configuration; files were preserved")
	}
	for _, share := range st.Shares {
		if !shareName(share.Name) || sharePathShape(share.Path) != nil || !sharingMountPath(share.Mountpoint) || !childOf(share.Path, share.Mountpoint) || share.Volume == "" {
			return reject("Invalid sharing configuration; files were preserved")
		}
		for _, v := range append(append([]string{}, share.Readers...), share.Writers...) {
			if _, err := systemops.Name(strings.TrimPrefix(v, "@")); err != nil {
				return err
			}
		}
		for _, v := range share.Clients {
			if _, err := sharingNetwork(v); err != nil {
				return err
			}
		}
	}
	for username, record := range st.Accounts {
		if !homeAccountName(username) || record == nil {
			return reject("Invalid sharing account state; files were preserved")
		}
	}
	return nil
}

func (s *sharingService) save(st sharingState) error {
	if err := validateSharingState(st); err != nil {
		return err
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.write(s.state, string(raw), 0600)
}
func (s *sharingService) locked() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(s.lock), 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(s.lock, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		return nil, reject("A sharing operation is already in progress")
	}
	return func() { unix.Close(fd) }, nil
}
func (s *sharingService) command(ctx context.Context, args []string, op bool, r *systemops.Reporter) (string, error) {
	raw, err := s.run(ctx, args, systemops.CommandOptions{Operation: op, Reporter: r})
	return strings.TrimSpace(string(raw)), err
}
func (s *sharingService) jsonCommand(ctx context.Context, args []string, v any) error {
	raw, err := s.run(ctx, args, systemops.CommandOptions{})
	if err != nil {
		return err
	}
	return systemops.Decode(raw, v)
}

type sharingMount struct {
	Target string `json:"target"`
	FSType string `json:"fstype"`
	UUID   string `json:"uuid"`
	Source string `json:"source"`
	Label  string `json:"label"`
}

func (s *sharingService) readLocation(ctx context.Context, path string) (sharingMount, error) {
	var row sharingMount
	if err := sharePathShape(path); err != nil {
		return row, err
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if os.IsNotExist(err) {
			return row, reject("Directory does not exist")
		}
		if err != nil {
			return row, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return row, reject("Links in the mount path are not allowed")
		}
		if p == path && !info.IsDir() {
			return row, reject("Directory does not exist")
		}
		if p == "/" {
			break
		}
	}
	var result struct {
		Filesystems []sharingMount `json:"filesystems"`
	}
	if err := s.jsonCommand(ctx, []string{"findmnt", "--json", "--target", path, "--output", "UUID,SOURCE,TARGET,FSTYPE"}, &result); err != nil {
		return row, err
	}
	if len(result.Filesystems) != 1 {
		return row, reject("Shared volume is not mounted")
	}
	row = result.Filesystems[0]
	if sharingVolume(row) == "" || row.Target == "" || row.Target == "/" || !childOf(path, row.Target) || slices.Contains([]string{"nfs", "nfs4", "cifs", "autofs"}, row.FSType) {
		return row, reject("The shared folder must be on a mounted local volume")
	}
	return row, nil
}
func sharingVolume(row sharingMount) string {
	if row.UUID != "" {
		return row.UUID
	}
	return row.Source
}
func (s *sharingService) normalize(ctx context.Context, p map[string]any) (sharedFolder, error) {
	result := sharedFolder{Name: stringParam(p, "name"), Path: stringParam(p, "path"), Clients: []string{}, Readers: []string{}, Writers: []string{}}
	if !shareName(result.Name) {
		return result, reject("Choose a unique share name using letters, numbers, dots, dashes or underscores")
	}
	row, err := s.locate(ctx, result.Path)
	if err != nil {
		return result, err
	}
	result.Volume = sharingVolume(row)
	result.Mountpoint = row.Target
	for _, key := range []string{"smb", "nfs", "readOnly"} {
		if _, ok := p[key].(bool); !ok {
			return result, reject("Protocol settings must be true or false")
		}
	}
	result.SMB = p["smb"].(bool)
	result.NFS = p["nfs"].(bool)
	result.ReadOnly = p["readOnly"].(bool)
	clients := ""
	if value, present := p["clients"]; present {
		var ok bool
		clients, ok = value.(string)
		if !ok {
			return result, reject("Enter NFS clients")
		}
	}
	for _, v := range strings.Split(clients, ",") {
		if strings.TrimSpace(v) == "" {
			continue
		}
		network, err := sharingNetwork(strings.TrimSpace(v))
		if err != nil {
			return result, reject("Specify NFS clients as IP addresses or subnets")
		}
		if !slices.Contains(result.Clients, network) {
			result.Clients = append(result.Clients, network)
		}
	}
	sort.Strings(result.Clients)
	if result.NFS && (len(result.Clients) == 0 || len(result.Clients) > 32) {
		return result, reject("Specify at least one NFS client or subnet")
	}
	for _, key := range []string{"readers", "writers"} {
		values := []string{}
		if value, present := p[key]; present {
			switch entries := value.(type) {
			case []string:
				values = entries
			case []any:
				for _, entry := range entries {
					text, ok := entry.(string)
					if !ok {
						return result, reject("Invalid access entry")
					}
					values = append(values, text)
				}
			default:
				return result, reject("Invalid access list")
			}
		}
		if len(values) > 128 {
			return result, reject("Invalid access list")
		}

		normalized := []string{}
		for _, v := range values {
			name := strings.TrimPrefix(v, "@")
			if _, err = systemops.Name(name); err != nil {
				return result, err
			}
			if strings.HasPrefix(v, "@") {
				groups, e := s.groups()
				if e != nil {
					return result, e
				}
				if _, ok := getgrnam(groups, name); !ok {
					return result, reject("Selected user or group no longer exists")
				}
			} else {
				u, e := s.user(v)
				if e != nil {
					return result, reject("Selected user or group no longer exists")
				}
				if e = s.normal(u); e != nil {
					return result, e
				}
			}
			if !slices.Contains(normalized, v) {
				normalized = append(normalized, v)
			}
		}
		sort.Strings(normalized)
		if key == "readers" {
			result.Readers = normalized
		} else {
			result.Writers = normalized
		}
	}
	if result.SMB && len(result.Readers)+len(result.Writers) == 0 {
		return result, reject("Select users or groups allowed to access SMB")
	}
	return result, nil
}
func SharingQuery(ctx context.Context, view, target, user string) (json.RawMessage, error) {
	s := defaultSharing()
	switch view {
	case "sharing":
		return s.query(ctx)
	case "share-folders":
		return s.folders(ctx, target, user)
	case "nfs":
		return s.nfsQuery()
	}
	return nil, systemops.ErrNoRoute
}
func IsSharing(action string) bool {
	return slices.Contains([]string{"share.save", "share.remove", "share.account", "share.disconnect", "share.recover", "nfs.export", "nfs.export-remove"}, action)
}
func PlanSharing(ctx context.Context, action string, p map[string]any) (json.RawMessage, error) {
	return defaultSharing().plan(ctx, action, p)
}
func ExecuteSharing(ctx context.Context, action string, p map[string]any, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	return defaultSharing().execute(ctx, action, p, expected, r)
}
func (s *sharingService) plan(ctx context.Context, action string, p map[string]any) (json.RawMessage, error) {
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	pending, err := sharingExists(s.journal)
	if err != nil {
		return nil, err
	}
	if action != "share.recover" {
		if pending {
			return nil, reject(sharingPending)
		}
		changed, err := s.drift(st)
		if err != nil {
			return nil, err
		}
		if changed {
			return nil, reject(sharingDrift)
		}
	}
	if action == "nfs.export" || action == "nfs.export-remove" {
		return s.nfsPlan(ctx, action, p)
	}
	target := stringParam(p, "target")
	details := []any{}
	var location any
	switch action {
	case "share.save":
		share, err := s.normalize(ctx, p)
		if err != nil {
			return nil, err
		}
		found := false
		for _, old := range st.Shares {
			if old.Name == target {
				found = true
			} else if strings.EqualFold(old.Name, share.Name) || old.Path == share.Path {
				return nil, reject("This name or folder is already shared")
			}
		}
		if target != "" && !found {
			return nil, reject("Shared folder no longer exists")
		}
		exports, err := s.nfsEntries()
		if err != nil {
			return nil, err
		}
		for _, e := range exports {
			if e.Path == share.Path {
				return nil, reject("This folder has a legacy NFS publication. Remove that publication first; files are preserved.")
			}
		}
		id, err := s.identity(share.Path)
		if err != nil {
			return nil, err
		}
		location = []any{share, id}
		target = share.Name
		details = []any{share.Path, "SMB: " + pythonBool(share.SMB), "NFS: " + pythonBool(share.NFS), "Existing files and Unix permissions are preserved. Protocol permissions cannot grant more access than Linux permissions."}
	case "share.remove":
		if !slices.ContainsFunc(st.Shares, func(v sharedFolder) bool { return v.Name == target }) {
			return nil, reject("Shared folder no longer exists")
		}
		details = []any{"Stop publishing this folder. Files and permissions are preserved. Connected clients may be disconnected."}
	case "share.account", "share.disconnect":
		if _, err = systemops.Name(target); err != nil {
			return nil, err
		}
		u, err := s.user(target)
		if err != nil {
			return nil, err
		}
		if err = s.normal(u); err != nil {
			return nil, err
		}
		if action == "share.disconnect" {
			details = []any{"Disconnect all SMB sessions for this user. Active transfers may be interrupted."}
		} else {
			enabled, ok := p["enabled"].(bool)
			if !ok {
				return nil, reject("Choose SMB access state")
			}
			message := "Disable SMB access and disconnect existing SMB sessions"
			if enabled {
				message = "Enable SMB access on the next successful panel password login or password change"
			}
			details = []any{message}
		}
	case "share.recover":
		target = "sharing"
		details = []any{"Restore the last saved managed configuration. External edits to managed files will be replaced; data files are preserved."}
	default:
		return nil, reject("Unknown sharing operation")
	}
	values := []any{st}
	for _, path := range []string{s.smb, s.exports, s.journal, s.passwd, s.group} {
		text, err := sharingText(path)
		if err != nil {
			return nil, err
		}
		values = append(values, text)
	}
	if location != nil {
		values = append(values, location)
	}
	fp, err := fingerprint(action, p, values)
	if err != nil {
		return nil, err
	}
	return marshal(map[string]any{"target": target, "confirmation": target, "details": details, "fingerprint": fp})
}
func pythonBool(v bool) string {
	if v {
		return "True"
	}
	return "False"
}
func (s *sharingService) execute(ctx context.Context, action string, p map[string]any, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	unlock, err := s.locked()
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer unlock()
	plan, err := s.plan(ctx, action, p)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	var fresh struct{ Fingerprint string }
	if err = json.Unmarshal(plan, &fresh); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if expected == "" || expected != fresh.Fingerprint {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	if r != nil {
		if err = r.Checkpoint(); err != nil {
			return nil, systemops.BeforeMutation(err)
		}
		r.Cancellable(false)
	}
	if action == "nfs.export" || action == "nfs.export-remove" {
		return s.nfsExecute(ctx, action, p, r)
	}
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	target := stringParam(p, "target")
	switch action {
	case "share.recover":
		err = s.recover(ctx, r)
	case "share.disconnect":
		err = s.disconnect(ctx, target, r)
	case "share.account":
		u, e := s.user(target)
		if e != nil {
			return nil, e
		}
		record := &sharedAccount{UID: &u.UID, Enabled: p["enabled"].(bool), Status: "pending"}
		if !record.Enabled {
			if err = s.disable(ctx, target, r); err != nil {
				return nil, err
			}
			record.Status = "disabled"
		}
		st.Accounts[target] = record
		err = s.save(st)
	default:
		st.Shares = slices.DeleteFunc(st.Shares, func(v sharedFolder) bool { return v.Name == target })
		if action == "share.save" {
			share, e := s.normalize(ctx, p)
			if e != nil {
				return nil, e
			}
			st.Shares = append(st.Shares, share)
		}
		if slices.ContainsFunc(st.Shares, func(v sharedFolder) bool { return v.SMB }) {
			main, e := sharingText(s.mainConfig)
			if e != nil {
				return nil, e
			}
			if !s.tool("smbpasswd") || !strings.Contains(main, "include = /etc/samba/panasms-shares.conf") {
				return nil, reject("Samba server integration is not installed")
			}
		}
		if target != "" && s.tool("smbcontrol") {
			if _, err = s.run(ctx, []string{"smbcontrol", "smbd", "close-share", target}, systemops.CommandOptions{Accepted: []int{0, 1}, Operation: true, Reporter: r}); err != nil {
				return nil, err
			}
		}
		err = s.apply(ctx, st, r)
	}
	if err != nil {
		return nil, err
	}
	return marshal(map[string]string{"message": "Shared folder settings updated"})
}
func (s *sharingService) query(ctx context.Context) (json.RawMessage, error) {
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	sessions := map[string]any{}
	if s.tool("smbstatus") {
		raw, e := s.run(ctx, []string{"smbstatus", "--json"}, systemops.CommandOptions{Timeout: 10 * time.Second})
		if e != nil || systemops.Decode(raw, &sessions) != nil {
			sessions = map[string]any{"error": "SMB session information unavailable"}
		}
	}
	for username, record := range st.Accounts {
		if record.Enabled && record.Status == "ready" {
			revision, e := s.revision(username)
			if e != nil {
				return nil, e
			}
			if revision != record.PasswordRevision {
				record.Status = "pending"
			}
		}
		record.PasswordRevision = ""
	}
	changed, err := s.drift(st)
	if err != nil {
		return nil, err
	}
	pending, err := sharingExists(s.journal)
	if err != nil {
		return nil, err
	}
	services := map[string]string{}
	for _, name := range []string{"smbd", "nfs-kernel-server"} {
		raw, e := s.run(ctx, []string{"systemctl", "is-active", name}, systemops.CommandOptions{Accepted: []int{0, 3, 4}})
		if e != nil {
			return nil, e
		}
		services[name] = strings.TrimSpace(string(raw))
	}
	return marshal(map[string]any{"shares": st.Shares, "accounts": st.Accounts, "drift": changed, "recovery": pending, "smbAvailable": s.tool("smbpasswd"), "sessions": sessions, "services": services})
}
func (s *sharingService) folders(ctx context.Context, target, user string) (json.RawMessage, error) {
	var rows struct {
		Filesystems []sharingMount `json:"filesystems"`
	}
	if err := s.jsonCommand(ctx, []string{"findmnt", "--json", "--list", "--output", "TARGET,FSTYPE,SOURCE,LABEL"}, &rows); err != nil {
		return nil, err
	}
	roots := []map[string]string{}
	seen := map[string]bool{}
	for _, row := range rows.Filesystems {
		if row.Target == "/" || seen[row.Target] || !slices.Contains([]string{"ext2", "ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs", "ntfs3"}, row.FSType) {
			continue
		}
		if _, err := s.locate(ctx, row.Target); err != nil {
			continue
		}
		name := row.Label
		if name == "" {
			name = filepath.Base(row.Target)
		}
		roots = append(roots, map[string]string{"name": name, "path": row.Target})
		seen[row.Target] = true
	}
	sort.Slice(roots, func(i, j int) bool { return strings.ToLower(roots[i]["name"]) < strings.ToLower(roots[j]["name"]) })
	if user != "" {
		u, err := s.user(user)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(roots, func(root map[string]string) bool { return childOf(u.Dir, root["path"]) }) {
			if _, err = s.locate(ctx, u.Dir); err == nil {
				roots = append([]map[string]string{{"name": "Home", "path": u.Dir}}, roots...)
			}
		}
	}
	folders := []map[string]string{}
	if target != "" {
		if _, err := s.locate(ctx, target); err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(roots, func(root map[string]string) bool { return childOf(target, root["path"]) }) {
			return nil, reject("Choose a folder on a mounted local volume")
		}
		dir, err := os.Open(target)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		for {
			entries, e := dir.ReadDir(128)
			for _, entry := range entries {
				if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && entry.Name() != "lost+found" {
					folders = append(folders, map[string]string{"name": entry.Name(), "path": filepath.Join(target, entry.Name())})
					if len(folders) == 1000 {
						break
					}
				}
			}
			if e != nil || len(folders) == 1000 {
				if e != nil && e != io.EOF {
					return nil, e
				}
				break
			}
		}
		sort.Slice(folders, func(i, j int) bool { return strings.ToLower(folders[i]["name"]) < strings.ToLower(folders[j]["name"]) })
	}
	return marshal(map[string]any{"roots": roots, "path": target, "folders": folders})
}

func SharingRecovery() (json.RawMessage, error) { return defaultSharing().recoveryView() }
func (s *sharingService) recoveryView() (json.RawMessage, error) {
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	changed, err := s.drift(st)
	if err != nil {
		return nil, err
	}
	pending, err := sharingExists(s.journal)
	if err != nil {
		return nil, err
	}
	exports, err := s.nfsEntries()
	if err != nil {
		return nil, err
	}
	return marshal(map[string]any{"shares": st.Shares, "exports": exports, "drift": changed, "recovery": pending})
}
