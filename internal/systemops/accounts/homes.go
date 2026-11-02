package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type homeService struct {
	defaults, passwd, journal, nologin, proc, lock string
	users                                          func() ([]passwdUser, error)
	run                                            func(context.Context, []string, systemops.CommandOptions) ([]byte, error)
	write                                          func(string, string, os.FileMode) error
}

func defaultHomes() *homeService {
	return &homeService{
		defaults: "/etc/default/useradd", passwd: "/etc/passwd", journal: "/var/lib/panasms-agent/home-move.json",
		nologin: "/run/nologin", proc: "/proc", lock: "/var/lib/panasms-agent/home-move.lock",
		users: getpwall, run: systemops.Command, write: systemops.AtomicWrite,
	}
}

func (s *homeService) base() (string, error) {
	raw, err := os.ReadFile(s.defaults)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "HOME=") {
			return systemops.CleanPath(strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "HOME=")), "\"'"))
		}
	}
	return "/home", nil
}

func homeAffected(source string, users []passwdUser) []passwdUser {
	result := []passwdUser{}
	for _, u := range users {
		if strings.HasPrefix(u.Dir, source+"/") {
			result = append(result, u)
		}
	}
	return result
}

func homeValidateAffected(source, target string, all []passwdUser) error {
	counts := map[string]int{}
	for _, u := range all {
		counts[u.Name]++
	}
	for _, u := range homeAffected(source, all) {
		_, oldErr := systemops.CleanPath(u.Dir)
		_, newErr := systemops.CleanPath(target + strings.TrimPrefix(u.Dir, source))
		if !homeAccountName(u.Name) || counts[u.Name] != 1 || oldErr != nil || newErr != nil {
			return reject("Invalid home-move account state; data was preserved")
		}
	}
	return nil
}

func (s *homeService) query() (json.RawMessage, error) {
	source, err := s.base()
	if err != nil {
		return nil, err
	}
	users, err := s.users()
	if err != nil {
		return nil, err
	}
	rows := []map[string]string{}
	for _, u := range homeAffected(source, users) {
		rows = append(rows, map[string]string{"name": u.Name, "home": u.Dir})
	}
	_, err = os.Lstat(s.journal)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return marshal(map[string]any{"path": source, "users": rows, "recovery": err == nil})
}

func HomesQuery() (json.RawMessage, error) { return defaultHomes().query() }

func HomesPreflight(ctx context.Context, destination string) (json.RawMessage, error) {
	result, err := defaultHomes().plan(ctx, "homes.move", map[string]any{"destination": destination})
	var busy *homeBusy
	if errors.As(err, &busy) {
		return marshal(map[string]any{"blockers": busy.blockers})
	}
	return result, err
}

func PlanHomes(ctx context.Context, action string, params map[string]any) (json.RawMessage, error) {
	return defaultHomes().plan(ctx, action, params)
}

func (s *homeService) jsonCommand(ctx context.Context, args []string, value any) error {
	raw, err := s.run(ctx, args, systemops.CommandOptions{})
	if err != nil {
		return err
	}
	return systemops.Decode(raw, value)
}

func (s *homeService) mounts(ctx context.Context) ([]mount, error) {
	var result struct {
		Filesystems []mount `json:"filesystems"`
	}
	err := s.jsonCommand(ctx, []string{"findmnt", "--json", "--list", "--output", "TARGET,FSTYPE,OPTIONS,MAJ:MIN,UUID"}, &result)
	return result.Filesystems, err
}

func (s *homeService) idle(ctx context.Context, source string, users []passwdUser) error {
	rows, err := s.blockers(ctx, source, users)
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		return &homeBusy{blockers: rows}
	}
	return nil
}

func (s *homeService) inspect(ctx context.Context, destination string) (string, string, []passwdUser, error) {
	if _, err := os.Lstat(s.journal); err == nil {
		return "", "", nil, reject("An interrupted home move must be recovered first")
	} else if !os.IsNotExist(err) {
		return "", "", nil, err
	}
	source, err := s.base()
	if err != nil {
		return "", "", nil, err
	}
	target, err := systemops.CleanPath(destination)
	if err != nil {
		return "", "", nil, err
	}
	if childOf(source, target) || childOf(target, source) {
		return "", "", nil, reject("Home folder locations must not overlap")
	}
	allowed := func(path string) bool {
		return path == "/home" || strings.HasPrefix(path, "/home/") || strings.HasPrefix(path, "/srv/") || strings.HasPrefix(path, "/mnt/")
	}
	if !allowed(source) {
		return "", "", nil, reject("Unsupported current home location")
	}
	if !allowed(target) {
		return "", "", nil, reject("Choose a new folder under /home, /srv or /mnt")
	}
	for _, path := range []string{source, target} {
		if err := noLinks(path); err != nil {
			return "", "", nil, err
		}
	}
	old, err := os.Stat(source)
	if err != nil || !old.IsDir() {
		return "", "", nil, reject("The source and destination parent must exist; the destination must be a new folder")
	}
	parent, err := os.Stat(filepath.Dir(target))
	if err != nil || !parent.IsDir() {
		return "", "", nil, reject("The source and destination parent must exist; the destination must be a new folder")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return "", "", nil, reject("The source and destination parent must exist; the destination must be a new folder")
	}
	mounts, err := s.mounts(ctx)
	if err != nil {
		return "", "", nil, err
	}
	best := mount{}
	for _, m := range mounts {
		if childOf(m.Target, source) {
			return "", "", nil, reject("The home folder contains mounts; unmount them before moving")
		}
		if childOf(filepath.Dir(target), m.Target) && len(m.Target) > len(best.Target) {
			best = m
		}
	}
	if (strings.HasPrefix(target, "/srv/") || strings.HasPrefix(target, "/mnt/")) && (best.Target == "/" || best.Target == "") {
		return "", "", nil, reject("The home volume is unavailable or the path is a volume root")
	}
	if err := homeVolume(best); err != nil {
		return "", "", nil, err
	}
	all, err := s.users()
	if err != nil {
		return "", "", nil, err
	}
	if err := homeValidateAffected(source, target, all); err != nil {
		return "", "", nil, err
	}
	users := homeAffected(source, all)
	for _, u := range all {
		if strings.HasPrefix(u.Dir, source+"/") {
			if u.UID == 0 {
				return "", "", nil, reject("Root home cannot be moved")
			}
			if info, err := os.Stat(u.Dir); err != nil || !info.IsDir() {
				return "", "", nil, reject("Home folder unavailable: " + u.Name)
			}
			if err := noLinks(u.Dir); err != nil {
				return "", "", nil, err
			}
		} else if u.Dir != "/" && u.Dir != "/nonexistent" && (childOf(u.Dir, target) || childOf(target, u.Dir)) {
			return "", "", nil, reject("The path overlaps another user's home folder")
		}
	}
	if err := s.idle(ctx, source, users); err != nil {
		return "", "", nil, err
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		return "", "", nil, reject("Install rsync before moving home folders")
	}
	return source, target, users, nil
}

func (s *homeService) plan(ctx context.Context, action string, params map[string]any) (json.RawMessage, error) {
	if action == "homes.recover" {
		raw, err := os.ReadFile(s.journal)
		if os.IsNotExist(err) {
			return nil, reject("No interrupted home move")
		}
		if err != nil {
			return nil, err
		}
		fp, err := fingerprint(action, params, string(raw))
		if err != nil {
			return nil, err
		}
		return marshal(map[string]any{"target": "homes", "confirmation": "homes", "details": []string{}, "fingerprint": fp})
	}
	if action != "homes.move" {
		return nil, reject("Unknown home operation")
	}
	source, target, users, err := s.inspect(ctx, stringParam(params, "destination"))
	if err != nil {
		return nil, err
	}
	passwd, err := os.ReadFile(s.passwd)
	if err != nil {
		return nil, err
	}
	identity, err := homeIdentity(source)
	if err != nil {
		return nil, err
	}
	parent, err := homeIdentity(filepath.Dir(target))
	if err != nil {
		return nil, err
	}
	fp, err := fingerprint(action, params, []any{source, string(passwd), identity, parent})
	if err != nil {
		return nil, err
	}
	details := []string{source + " → " + target}
	for _, u := range users {
		details = append(details, u.Name+": "+u.Dir+" → "+target+strings.TrimPrefix(u.Dir, source))
	}
	return marshal(map[string]any{"target": target, "confirmation": target, "details": details, "fingerprint": fp})
}

func homeIdentity(path string) ([]uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, reject("Home volume changed or is unavailable; data was preserved")
	}
	st := info.Sys().(*syscall.Stat_t)
	return []uint64{uint64(st.Dev), st.Ino}, nil
}

func homePin(path string, expected []uint64) (*os.File, error) {
	if err := noLinks(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, reject("Home volume changed or is unavailable; data was preserved")
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil && len(expected) != 0 {
		st := info.Sys().(*syscall.Stat_t)
		if len(expected) != 2 || uint64(st.Dev) != expected[0] || st.Ino != expected[1] {
			err = reject("Home volume changed or is unavailable; data was preserved")
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func homePinnedPath(f *os.File) string {
	return "/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
}

func (s *homeService) locked() (func(), error) {
	if err := os.MkdirAll(filepath.Dir(s.lock), 0700); err != nil {
		return nil, err
	}
	fd, err := unix.Open(s.lock, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		return nil, reject("A home-folder operation is already in progress")
	}
	return func() { unix.Close(fd) }, nil
}

func ExecuteHomes(ctx context.Context, action string, params map[string]any, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	return defaultHomes().executeVerified(ctx, action, params, expected, r)
}

func (s *homeService) executeVerified(ctx context.Context, action string, params map[string]any, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	unlock, err := s.locked()
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer unlock()
	planned, err := s.plan(ctx, action, params)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	var plan struct{ Fingerprint string }
	if err := systemops.Decode(planned, &plan); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if plan.Fingerprint != expected || expected == "" {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	if action == "homes.recover" {
		return s.recover(ctx, r)
	}
	return s.execute(ctx, params, expected, r)
}

func (s *homeService) execute(ctx context.Context, params map[string]any, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	source, target, users, err := s.inspect(ctx, stringParam(params, "destination"))
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	sourceDir, err := homePin(source, nil)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer sourceDir.Close()
	parent, err := homePin(filepath.Dir(target), nil)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer parent.Close()
	sourceIdentity, err := homeIdentity(homePinnedPath(sourceDir))
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	parentIdentity, err := homeIdentity(homePinnedPath(parent))
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	raw, err := s.run(ctx, []string{"du", "-sx", "--block-size=1", "--", homePinnedPath(sourceDir) + "/"}, systemops.CommandOptions{Timeout: 24 * time.Hour})
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return nil, systemops.BeforeMutation(reject("Could not determine home-folder size"))
	}
	size, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(parent.Fd()), &fs); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if fs.Bavail*uint64(fs.Bsize) <= size+64*1024*1024 {
		return nil, systemops.BeforeMutation(reject("Not enough free space to copy home folders"))
	}
	// Size calculation can be lengthy; revalidate consent before creating state.
	planned, err := s.plan(ctx, "homes.move", params)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	var current struct{ Fingerprint string }
	if err := systemops.Decode(planned, &current); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if current.Fingerprint != expected {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	for path, identity := range map[string][]uint64{source: sourceIdentity, filepath.Dir(target): parentIdentity} {
		if err := homeCheckIdentity(path, identity); err != nil {
			return nil, systemops.BeforeMutation(err)
		}
	}
	if _, err := os.Lstat(s.nologin); !os.IsNotExist(err) {
		return nil, systemops.BeforeMutation(reject("System maintenance is already in progress"))
	}
	state := homeJournal{Source: source, Target: target, Phase: "copying", Users: []homeJournalUser{}, Nologin: "PaNasMs is moving home folders. Please try again shortly.\n"}
	state.SourceIdentity = sourceIdentity
	for _, u := range users {
		uid, gid := u.UID, u.GID
		state.Users = append(state.Users, homeJournalUser{Name: u.Name, Old: u.Dir, New: target + strings.TrimPrefix(u.Dir, source), UID: &uid, GID: &gid})
	}
	state.Backup, err = os.MkdirTemp(filepath.Dir(source), ".panasms-home-")
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	state.BackupIdentity, err = homeIdentity(state.Backup)
	if err == nil {
		err = s.validateJournal(&state)
	}
	if err == nil {
		err = s.save(&state)
	}
	if err != nil {
		os.Remove(state.Backup)
		return nil, systemops.BeforeMutation(err)
	}
	if err := s.move(ctx, &state, users, parent, parentIdentity, r); err != nil {
		if _, recoveryErr := s.recover(context.WithoutCancel(ctx), r); recoveryErr != nil {
			return nil, reject("Home move interrupted. Recovery is required; original data was preserved.")
		}
		return nil, err
	}
	return marshal(map[string]any{"message": "Home folders moved and user paths updated"})
}

func (s *homeService) move(ctx context.Context, state *homeJournal, users []passwdUser, parent *os.File, parentIdentity []uint64, r *systemops.Reporter) error {
	source, err := homePin(state.Source, state.SourceIdentity)
	if err != nil {
		return err
	}
	defer source.Close()
	if err := s.createNologin(state); err != nil {
		return err
	}
	run := func(args ...string) error {
		_, err := s.run(ctx, args, systemops.CommandOptions{Operation: true, Reporter: r})
		return err
	}
	mount := func(args ...string) error {
		r.Stage(systemops.CommandStage("mount"))
		// The new move_mount API does not resolve these pinned /proc FD targets.
		argv := append([]string{"/usr/bin/env", "LIBMOUNT_FORCE_MOUNT2=always", "mount"}, args...)
		_, err := s.run(ctx, argv, systemops.CommandOptions{Operation: true})
		return err
	}
	if err := s.idle(ctx, state.Source, users); err != nil {
		return err
	}
	sourceRef := homePinnedPath(source)
	if err := mount("--no-canonicalize", "--bind", sourceRef, sourceRef); err != nil {
		return err
	}
	// The original FD still names the parent mount; remount only the new bind.
	bound, err := homePin(state.Source, state.SourceIdentity)
	if err != nil {
		return err
	}
	err = mount("--no-canonicalize", "-o", "remount,bind,ro", homePinnedPath(bound), homePinnedPath(bound))
	bound.Close()
	if err != nil {
		return err
	}
	if err := s.idle(ctx, state.Source, users); err != nil {
		return err
	}
	if err := homeCheckIdentity(filepath.Dir(state.Target), parentIdentity); err != nil {
		return err
	}
	created := filepath.Join(homePinnedPath(parent), filepath.Base(state.Target))
	if err := os.Mkdir(created, 0700); err != nil {
		return err
	}
	createdIdentity, err := homeIdentity(created)
	if err != nil {
		return err
	}
	target, err := homePin(state.Target, createdIdentity)
	if err != nil {
		return err
	}
	defer target.Close()
	state.TargetIdentity, err = homeIdentity(homePinnedPath(target))
	if err != nil {
		return err
	}
	if err := s.save(state); err != nil {
		return err
	}
	args := []string{"rsync", "-aHAXS", "--numeric-ids"}
	sourcePath, targetPath := homePinnedPath(source)+"/", homePinnedPath(target)+"/"
	r.Stage(systemops.CommandStage("rsync"))
	if _, err := systemops.Copying(ctx, r, append(args, sourcePath, targetPath), 0); err != nil {
		return err
	}
	for i, u := range state.Users {
		relative, _ := filepath.Rel(state.Target, u.New)
		identity, err := homeIdentity(filepath.Join(homePinnedPath(target), relative))
		if err != nil {
			return err
		}
		state.Users[i].NewIdentity = identity
	}
	verify := append([]string{}, args...)
	verify = append(verify, "--dry-run", "--checksum", "--itemize-changes", "--delete", sourcePath, targetPath)
	changes, err := systemops.Copying(ctx, r, verify, 0)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(changes)) != "" {
		return reject("Home copy verification failed; original data was preserved")
	}
	if err := run("sync", "-f", targetPath); err != nil {
		return err
	}
	if err := s.idle(ctx, state.Source, users); err != nil {
		return err
	}
	r.Cancellable(false)
	if err := r.Checkpoint(); err != nil {
		return err
	}
	if err := homeCheckIdentity(state.Source, state.SourceIdentity); err != nil {
		return err
	}
	if err := homeCheckIdentity(state.Target, state.TargetIdentity); err != nil {
		return err
	}
	for _, u := range state.Users {
		if err := homeCheckIdentity(u.New, u.NewIdentity); err != nil {
			return err
		}
	}
	state.Phase = "switching"
	if err := s.save(state); err != nil {
		return err
	}
	for _, u := range state.Users {
		if err := run("usermod", "--home", u.New, "--", u.Name); err != nil {
			return err
		}
	}
	if err := run("useradd", "--defaults", "--base-dir", state.Target); err != nil {
		return err
	}
	state.Phase = "committed"
	if err := s.save(state); err != nil {
		return err
	}
	_, err = s.recover(ctx, r)
	return err
}
