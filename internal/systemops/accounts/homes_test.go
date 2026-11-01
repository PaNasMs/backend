package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"panasms.local/backend/internal/systemops"
)

type homeFixture struct {
	s        *homeService
	state    homeJournal
	current  passwdUser
	root     string
	commands [][]string
}

func newHomeFixture(t *testing.T, phase string) *homeFixture {
	t.Helper()
	f := &homeFixture{root: t.TempDir()}
	f.state = homeJournal{Source: filepath.Join(f.root, "source"), Target: filepath.Join(f.root, "target"), Backup: filepath.Join(f.root, ".panasms-home-test"), Phase: phase, Nologin: "owned home maintenance\n"}
	for _, p := range []string{f.state.Source, f.state.Target, f.state.Backup, f.state.Target + "/alice"} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.state.SourceIdentity, _ = homeIdentity(f.state.Source)
	f.state.TargetIdentity, _ = homeIdentity(f.state.Target)
	f.state.BackupIdentity, _ = homeIdentity(f.state.Backup)
	uid, gid := 15000, 15000
	f.state.Users = []homeJournalUser{{Name: "alice", Old: f.state.Source + "/alice", New: f.state.Target + "/alice", UID: &uid, GID: &gid}}
	f.current = passwdUser{Name: "alice", UID: uid, GID: gid, Dir: f.state.Users[0].New}
	f.s = &homeService{defaults: filepath.Join(f.root, "useradd"), passwd: filepath.Join(f.root, "passwd"), journal: filepath.Join(f.root, "journal"), nologin: filepath.Join(f.root, "nologin"), proc: filepath.Join(f.root, "proc"), lock: filepath.Join(f.root, "lock")}
	f.s.users = func() ([]passwdUser, error) { return []passwdUser{f.current}, nil }
	f.s.write = func(path, text string, mode os.FileMode) error { return os.WriteFile(path, []byte(text), mode) }
	f.s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		f.commands = append(f.commands, append([]string{}, args...))
		switch args[0] {
		case "findmnt":
			return []byte(`{"filesystems":[]}`), nil
		case "usermod":
			f.current.Dir = args[2]
		case "useradd":
			return nil, os.WriteFile(f.s.defaults, []byte("HOME="+args[3]+"\n"), 0600)
		case "sync":
		default:
			t.Fatalf("unexpected fixture command: %q", args)
		}
		return nil, nil
	}
	for path, data := range map[string]string{f.s.defaults: "HOME=" + f.state.Target + "\n", f.state.Source + "/original": "original", f.state.Target + "/copied": "copied"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.save(t)
	return f
}

func (f *homeFixture) save(t *testing.T) {
	t.Helper()
	if err := f.s.save(&f.state); err != nil {
		t.Fatal(err)
	}
}

func assertHomeFile(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || string(data) != expected {
		t.Fatalf("%s = %q, %v; want %q", path, data, err, expected)
	}
}

func TestHomesLegacySwitchingRecoveryRetainsBothCopies(t *testing.T) {
	f := newHomeFixture(t, "switching")
	f.state.SourceIdentity, f.state.TargetIdentity, f.state.BackupIdentity = nil, nil, nil
	f.state.Users[0].UID, f.state.Users[0].GID = nil, nil
	f.save(t)
	if _, err := f.s.recover(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if f.current.Dir != f.state.Users[0].Old {
		t.Fatal("partially switched user was not restored")
	}
	assertHomeFile(t, f.s.defaults, "HOME="+f.state.Source+"\n")
	assertHomeFile(t, f.state.Source+"/original", "original")
	assertHomeFile(t, f.state.Target+"/copied", "copied")
	for _, p := range []string{f.s.journal, f.s.nologin, f.state.Backup} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("fixture artifact retained: %s (%v)", p, err)
		}
	}
	if _, err := f.s.recover(context.Background(), nil); err != nil {
		t.Fatal("second recovery:", err)
	}
}

func TestHomesCommittedRecoveryAndRenameInterruption(t *testing.T) {
	for _, renamed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-rename", true: "after-rename"}[renamed], func(t *testing.T) {
			f := newHomeFixture(t, "committed")
			if renamed {
				if err := os.Rename(f.state.Source, filepath.Join(f.state.Backup, "previous")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.s.recover(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(f.state.Source); !os.IsNotExist(err) {
				t.Fatal("original tree retained", err)
			}
			assertHomeFile(t, f.state.Target+"/copied", "copied")
			if f.current.Dir != f.state.Users[0].New {
				t.Fatal("committed home was rolled back")
			}
			if _, err := f.s.recover(context.Background(), nil); err != nil {
				t.Fatal("second recovery:", err)
			}
		})
	}
}

func TestHomesRecoveryPreservesChangedTreesAndAccounts(t *testing.T) {
	for _, scenario := range []string{"source-replaced", "target-vanished", "backup-replaced", "user-home-changed", "uid-reused", "default-changed"} {
		t.Run(scenario, func(t *testing.T) {
			phase := "committed"
			if scenario == "source-replaced" {
				phase = "switching"
			}
			f := newHomeFixture(t, phase)
			switch scenario {
			case "source-replaced":
				if err := os.Rename(f.state.Source, f.root+"/saved-source"); err != nil {
					t.Fatal(err)
				}
				os.Mkdir(f.state.Source, 0700)
				os.WriteFile(f.state.Source+"/unrelated", []byte("keep"), 0600)
			case "target-vanished":
				if err := os.Rename(f.state.Target, f.root+"/saved-target"); err != nil {
					t.Fatal(err)
				}
			case "backup-replaced":
				previous := filepath.Join(f.state.Backup, "previous")
				if err := os.Rename(f.state.Source, f.root+"/saved-source"); err != nil {
					t.Fatal(err)
				}
				os.Mkdir(previous, 0700)
				os.WriteFile(previous+"/unrelated", []byte("keep"), 0600)
			case "user-home-changed":
				f.current.Dir = "/home/new-owner-choice"
			case "uid-reused":
				f.current.UID++
			case "default-changed":
				os.WriteFile(f.s.defaults, []byte("HOME=/home/new-choice\n"), 0600)
			}
			if _, err := f.s.recover(context.Background(), nil); err == nil {
				t.Fatal("changed state accepted")
			}
			if _, err := os.Stat(f.s.journal); err != nil {
				t.Fatal("recovery evidence removed", err)
			}
			if scenario == "backup-replaced" {
				assertHomeFile(t, f.state.Backup+"/previous/unrelated", "keep")
			}
			if scenario == "source-replaced" {
				assertHomeFile(t, f.state.Source+"/unrelated", "keep")
			}
			if scenario != "target-vanished" {
				assertHomeFile(t, f.state.Target+"/copied", "copied")
			}
		})
	}
}

func TestHomesRecoveryKeepsUnrelatedMaintenanceMarker(t *testing.T) {
	f := newHomeFixture(t, "copying")
	os.WriteFile(f.s.nologin, []byte("different maintenance\n"), 0600)
	if _, err := f.s.recover(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	assertHomeFile(t, f.s.nologin, "different maintenance\n")
	assertHomeFile(t, f.state.Source+"/original", "original")
	assertHomeFile(t, f.state.Target+"/copied", "copied")
}

func TestHomesRecoveryPlanIsReadOnlyAndStalePlanRejected(t *testing.T) {
	f := newHomeFixture(t, "switching")
	before, _ := os.ReadFile(f.s.journal)
	raw, err := f.s.plan(context.Background(), "homes.recover", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != 0 {
		t.Fatal("recovery planning executed commands")
	}
	assertHomeFile(t, f.s.journal, string(before))
	var plan struct{ Fingerprint string }
	json.Unmarshal(raw, &plan)
	os.WriteFile(f.s.journal, append(before, '\n'), 0600)
	if _, err := f.s.executeVerified(context.Background(), "homes.recover", map[string]any{}, plan.Fingerprint, nil); err == nil || !systemops.Unchanged(err) || !strings.Contains(err.Error(), "State has changed") {
		t.Fatal("stale recovery plan:", err)
	}
	assertHomeFile(t, f.state.Source+"/original", "original")
	assertHomeFile(t, f.state.Target+"/copied", "copied")
}

func TestHomesDefaultAndAffectedPaths(t *testing.T) {
	f := newHomeFixture(t, "copying")
	os.WriteFile(f.s.defaults, []byte("HOME='/srv/data/homes'\n"), 0600)
	base, err := f.s.base()
	if err != nil || base != "/srv/data/homes" {
		t.Fatal(base, err)
	}
	users := []passwdUser{{Name: "a", Dir: base + "/a"}, {Name: "b", Dir: base + "/nested/b"}, {Name: "other", Dir: base + "-other/a"}}
	if got := homeAffected(base, users); len(got) != 2 || got[1].Name != "b" {
		t.Fatal(got)
	}
}

func TestHomesBlockersGroupApplicationsWithoutCommandLines(t *testing.T) {
	f := newHomeFixture(t, "copying")
	f.current.UID = os.Getuid()
	if err := os.Mkdir(f.s.proc, 0700); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"900001", "900002", "900003"} {
		dir := filepath.Join(f.s.proc, pid)
		os.Mkdir(dir, 0700)
		state := "S"
		if pid == "900003" {
			state = "Z"
		}
		for name, data := range map[string]string{"status": "State:\t" + state + " (fixture)\n", "comm": "python3\n", "cgroup": "0::/system.slice/panasms-cloud-sync-user-15000.service\n", "cmdline": "secret command line must not be read"} {
			os.WriteFile(filepath.Join(dir, name), []byte(data), 0600)
		}
	}
	rows, err := f.s.blockers(context.Background(), f.state.Source, []passwdUser{f.current})
	if err != nil || len(rows) != 1 || len(rows[0].Processes) != 2 || rows[0].Title != "Cloud Sync" || rows[0].Kind != "cloudSync" || rows[0].Reason != "session" {
		t.Fatalf("blockers: %#v, %v", rows, err)
	}
	err = f.s.idle(context.Background(), f.state.Source, []passwdUser{f.current})
	var busy *homeBusy
	if !errors.As(err, &busy) || !systemops.IsRejected(err) || !strings.Contains(err.Error(), "alice: Cloud Sync") || strings.Contains(err.Error(), "secret") {
		t.Fatal(err)
	}
}

func TestHomesLockExcludesConcurrentRecoveryWithoutPlanWrites(t *testing.T) {
	f := newHomeFixture(t, "switching")
	if _, err := f.s.plan(context.Background(), "homes.recover", map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(f.s.lock); !os.IsNotExist(err) {
		t.Fatal("planning created a lock file", err)
	}
	unlock, err := f.s.locked()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if release, err := f.s.locked(); err == nil {
		release()
		t.Fatal("concurrent recovery acquired the lock")
	}
}

func TestHomeVolumeResolvesBtrfsMountDeviceAndRejectsRemovableMember(t *testing.T) {
	for _, scenario := range []string{"permanent", "usb-member", "unknown-volume"} {
		t.Run(scenario, func(t *testing.T) {
			bin := t.TempDir()
			devices := []map[string]any{{"name": "sda1", "maj:min": "8:1", "type": "part", "rm": false, "tran": "sata", "fstype": "btrfs", "uuid": "volume"}}
			if scenario == "usb-member" {
				devices = append(devices, map[string]any{"name": "sdb1", "maj:min": "8:17", "type": "part", "rm": false, "tran": "usb", "fstype": "btrfs", "uuid": "volume"})
			}
			deviceJSON, _ := json.Marshal(map[string]any{"blockdevices": devices})
			for command, output := range map[string]string{"lsblk": string(deviceJSON), "findmnt": `{"filesystems":[{"target":"/srv/data","options":"defaults"}]}`} {
				script := "#!/bin/sh\nprintf '%s' '" + output + "'\n"
				if err := os.WriteFile(filepath.Join(bin, command), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			uuid := "volume"
			if scenario == "unknown-volume" {
				uuid = "other"
			}
			err := homeVolume(mount{Target: "/srv/data", FSType: "btrfs", Options: "rw", Device: "0:25", UUID: uuid})
			if (err == nil) != (scenario == "permanent") {
				t.Fatal("Btrfs home policy:", scenario, err)
			}
		})
	}
}

func TestHomesRecoveryNeverFollowsReplacedBackupParent(t *testing.T) {
	f := newHomeFixture(t, "committed")
	run := f.s.run
	f.s.run = func(ctx context.Context, args []string, opts systemops.CommandOptions) ([]byte, error) {
		if args[0] == "sync" {
			if err := os.Rename(f.state.Backup, f.root+"/renamed-backup"); err != nil {
				t.Fatal(err)
			}
			os.Mkdir(f.state.Backup, 0700)
			os.Mkdir(f.state.Backup+"/previous", 0700)
			os.WriteFile(f.state.Backup+"/previous/unrelated", []byte("keep"), 0600)
		}
		return run(ctx, args, opts)
	}
	if _, err := f.s.recover(context.Background(), nil); err == nil {
		t.Fatal("replaced backup directory accepted")
	}
	assertHomeFile(t, f.state.Backup+"/previous/unrelated", "keep")
	assertHomeFile(t, f.state.Target+"/copied", "copied")
	if _, err := os.Stat(f.s.journal); err != nil {
		t.Fatal("recovery journal discarded", err)
	}
}

func TestHomesRecoveryPreservesReplacedMaintenanceMarkerWithSameText(t *testing.T) {
	f := newHomeFixture(t, "switching")
	if err := f.s.createNologin(&f.state); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.s.nologin, f.root+"/old-marker"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(f.s.nologin, []byte(f.state.Nologin), 0600)
	if _, err := f.s.recover(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	assertHomeFile(t, f.s.nologin, f.state.Nologin)
	assertHomeFile(t, f.state.Source+"/original", "original")
}

func TestHomesRecoveryHandlesInterruptedMaintenancePublication(t *testing.T) {
	f := newHomeFixture(t, "switching")
	temporary, err := os.CreateTemp(f.root, ".panasms-home-nologin-")
	if err != nil {
		t.Fatal(err)
	}
	temporary.WriteString(f.state.Nologin)
	info, _ := temporary.Stat()
	temporary.Close()
	st := info.Sys().(*syscall.Stat_t)
	f.state.NologinIdentity = []uint64{uint64(st.Dev), st.Ino}
	f.state.NologinTemp = temporary.Name()
	f.save(t)
	if _, err := f.s.recover(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(temporary.Name()); !os.IsNotExist(err) {
		t.Fatal("unpublished maintenance marker retained", err)
	}
	if _, err := os.Lstat(f.s.nologin); !os.IsNotExist(err) {
		t.Fatal("recovered maintenance marker retained", err)
	}
	assertHomeFile(t, f.state.Source+"/original", "original")
}

func TestHomesMaintenancePublicationWaitsForDurableJournal(t *testing.T) {
	f := newHomeFixture(t, "copying")
	f.s.write = func(string, string, os.FileMode) error { return errors.New("journal full") }
	if err := f.s.createNologin(&f.state); err == nil {
		t.Fatal("journal failure ignored")
	}
	if _, err := os.Lstat(f.s.nologin); !os.IsNotExist(err) {
		t.Fatal("maintenance published without recorded ownership", err)
	}
	if paths, _ := filepath.Glob(f.root + "/.panasms-home-nologin-*"); len(paths) != 0 {
		t.Fatal("temporary maintenance marker leaked", paths)
	}
}

func TestHomesRecoveryAcceptsExistingNSSNames(t *testing.T) {
	for _, name := range []string{"Alice.Example", "DOMAIN\\alice", "machine$", strings.Repeat("u", 32)} {
		t.Run(name, func(t *testing.T) {
			f := newHomeFixture(t, "committed")
			f.state.Users[0].Name, f.current.Name = name, name
			f.save(t)
			if _, err := f.s.recover(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			assertHomeFile(t, f.state.Target+"/copied", "copied")
			if _, err := os.Stat(f.s.journal); !os.IsNotExist(err) {
				t.Fatal("valid NSS account stranded recovery", err)
			}
		})
	}
}

func TestHomesCommittedRecoveryPreservesOriginalWhenUserCopyMissing(t *testing.T) {
	f := newHomeFixture(t, "committed")
	if err := os.Remove(f.state.Users[0].New); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.recover(context.Background(), nil); err == nil {
		t.Fatal("missing destination home accepted for destructive cleanup")
	}
	assertHomeFile(t, f.state.Backup+"/previous/original", "original")
	if _, err := os.Stat(f.s.journal); err != nil {
		t.Fatal("recovery evidence removed", err)
	}
}
