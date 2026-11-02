package accounts

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"panasms.local/backend/internal/systemops"
)

type homeJournalUser struct {
	Name        string   `json:"name"`
	Old         string   `json:"old"`
	New         string   `json:"new"`
	UID         *int     `json:"uid,omitempty"`
	GID         *int     `json:"gid,omitempty"`
	NewIdentity []uint64 `json:"newIdentity,omitempty"`
}

type homeJournal struct {
	Source          string            `json:"source"`
	Target          string            `json:"target"`
	Backup          string            `json:"backup"`
	Phase           string            `json:"phase"`
	Users           []homeJournalUser `json:"users"`
	Nologin         string            `json:"nologin,omitempty"`
	SourceIdentity  []uint64          `json:"sourceIdentity,omitempty"`
	TargetIdentity  []uint64          `json:"targetIdentity,omitempty"`
	BackupIdentity  []uint64          `json:"backupIdentity,omitempty"`
	NologinIdentity []uint64          `json:"nologinIdentity,omitempty"`
	NologinTemp     string            `json:"nologinTemp,omitempty"`
}

func (s *homeService) save(state *homeJournal) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.write(s.journal, string(raw), 0600)
}

func homeCheckIdentity(path string, expected []uint64) error {
	if err := noLinks(path); err != nil {
		return err
	}
	actual, err := homeIdentity(path)
	if err != nil || (len(expected) != 0 && !slices.Equal(actual, expected)) {
		return reject("Home volume changed or is unavailable; data was preserved")
	}
	return nil
}

func homeAccountName(name string) bool {
	return name != "" && !strings.HasPrefix(name, "-") && !strings.ContainsAny(name, ":\x00\r\n")
}

func (s *homeService) readJournal() (*homeJournal, error) {
	raw, err := os.ReadFile(s.journal)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state homeJournal
	if err := systemops.Decode(raw, &state); err != nil {
		return nil, err
	}
	if err := s.validateJournal(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (s *homeService) validateJournal(state *homeJournal) error {
	if state.Phase != "copying" && state.Phase != "switching" && state.Phase != "committed" {
		return reject("Unknown home-move recovery state; data was preserved")
	}
	for _, p := range []string{state.Source, state.Target, state.Backup} {
		if _, err := systemops.CleanPath(p); err != nil || p == "/" {
			return reject("Invalid home-move recovery path; data was preserved")
		}
		if err := noLinks(p); err != nil {
			return err
		}
	}
	if childOf(state.Source, state.Target) || childOf(state.Target, state.Source) || filepath.Dir(state.Backup) != filepath.Dir(state.Source) || !strings.HasPrefix(filepath.Base(state.Backup), ".panasms-home-") {
		return reject("Invalid home-move recovery path; data was preserved")
	}
	for _, id := range [][]uint64{state.SourceIdentity, state.TargetIdentity, state.BackupIdentity, state.NologinIdentity} {
		if len(id) != 0 && len(id) != 2 {
			return reject("Invalid home-move recovery identity; data was preserved")
		}
	}
	if state.NologinTemp != "" && (len(state.NologinIdentity) != 2 || filepath.Dir(state.NologinTemp) != filepath.Dir(s.nologin) || !strings.HasPrefix(filepath.Base(state.NologinTemp), ".panasms-home-nologin-")) {
		return reject("Invalid home maintenance marker; data was preserved")
	}
	seen := map[string]bool{}
	for _, u := range state.Users {
		if (len(u.NewIdentity) != 0 && len(u.NewIdentity) != 2) || (state.Phase == "committed" && (u.UID != nil || u.GID != nil) && len(u.NewIdentity) != 2) {
			return reject("Invalid home-move recovery identity; data was preserved")
		}
		if _, err := systemops.CleanPath(u.Old); err != nil {
			return err
		}
		if _, err := systemops.CleanPath(u.New); err != nil {
			return err
		}
		if !homeAccountName(u.Name) || seen[u.Name] || !strings.HasPrefix(u.Old, state.Source+"/") || u.New != state.Target+strings.TrimPrefix(u.Old, state.Source) {
			return reject("Invalid home-move account state; data was preserved")
		}
		seen[u.Name] = true
	}
	return nil
}

func (s *homeService) recoveryUsers(state *homeJournal) ([]passwdUser, error) {
	all, err := s.users()
	if err != nil {
		return nil, err
	}
	users := []passwdUser{}
	for _, saved := range state.Users {
		u, ok := getpwnam(all, saved.Name)
		if !ok || u.UID == 0 || (saved.UID != nil && u.UID != *saved.UID) || (saved.GID != nil && u.GID != *saved.GID) || (u.Dir != saved.Old && u.Dir != saved.New) || (state.Phase == "committed" && u.Dir != saved.New) {
			return nil, reject("Home account changed; recovery stopped and data was preserved")
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *homeService) unmountSource(ctx context.Context, state *homeJournal, r *systemops.Reporter) error {
	mounts, err := s.mounts(ctx)
	if err != nil {
		return err
	}
	for _, m := range mounts {
		if m.Target != state.Source && childOf(m.Target, state.Source) {
			return reject("The home folder contains mounts; data was preserved")
		}
	}
	for _, m := range mounts {
		if m.Target == state.Source {
			if err := homeCheckIdentity(state.Source, state.SourceIdentity); err != nil {
				return err
			}
			_, err := s.run(ctx, []string{"umount", "--", state.Source}, systemops.CommandOptions{Operation: true, Reporter: r})
			return err
		}
	}
	return nil
}

func (s *homeService) recover(ctx context.Context, r *systemops.Reporter) (json.RawMessage, error) {
	state, err := s.readJournal()
	if err != nil {
		return nil, err
	}
	if state == nil {
		return marshal(map[string]any{"message": "No interrupted home move"})
	}
	users, err := s.recoveryUsers(state)
	if err != nil {
		return nil, err
	}
	base, err := s.base()
	if err != nil {
		return nil, err
	}
	if (base != state.Source && base != state.Target) || (state.Phase == "committed" && base != state.Target) {
		return nil, reject("Default home location changed; recovery stopped and data was preserved")
	}
	var targetIdentity []uint64
	var target *os.File
	if state.Phase == "committed" {
		target, err = homePin(state.Target, state.TargetIdentity)
		if err != nil {
			return nil, err
		}
		defer target.Close()
		targetIdentity, err = homeIdentity(homePinnedPath(target))
		if err != nil {
			return nil, err
		}
	} else if err := homeCheckIdentity(state.Source, state.SourceIdentity); err != nil {
		return nil, err
	}
	var backup *os.File
	if _, err := os.Lstat(state.Backup); err == nil {
		backup, err = homePin(state.Backup, state.BackupIdentity)
		if err != nil {
			return nil, err
		}
		defer backup.Close()
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if state.Nologin != "" {
		if err := s.cleanNologinTemp(state); err != nil {
			return nil, err
		}
		if _, err := os.Lstat(s.nologin); os.IsNotExist(err) {
			if err := s.createNologin(state); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	if state.Phase != "committed" {
		for i, u := range state.Users {
			if users[i].Dir != u.Old {
				if _, err := s.run(ctx, []string{"usermod", "--home", u.Old, "--", u.Name}, systemops.CommandOptions{Operation: true, Reporter: r}); err != nil {
					return nil, err
				}
			}
		}
		if _, err := s.run(ctx, []string{"useradd", "--defaults", "--base-dir", state.Source}, systemops.CommandOptions{Operation: true, Reporter: r}); err != nil {
			return nil, err
		}
		if err := s.unmountSource(ctx, state, r); err != nil {
			return nil, err
		}
	} else {
		if err := s.unmountSource(ctx, state, r); err != nil {
			return nil, err
		}
		previous := ""
		if backup != nil {
			previous = filepath.Join(homePinnedPath(backup), "previous")
		}
		_, previousErr := os.Lstat(previous)
		if _, sourceErr := os.Lstat(state.Source); sourceErr == nil {
			if backup == nil {
				return nil, reject("Home backup folder is unavailable; data was preserved")
			}
			if previousErr == nil {
				return nil, reject("Both original and backup home folders exist; data was preserved")
			}
			if !os.IsNotExist(previousErr) {
				return nil, previousErr
			}
			if err := homeCheckIdentity(state.Source, state.SourceIdentity); err != nil {
				return nil, err
			}
			if err := os.Rename(state.Source, previous); err != nil {
				return nil, err
			}
			if _, err := s.run(ctx, []string{"sync", "-f", state.Backup}, systemops.CommandOptions{Operation: true, Reporter: r}); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(sourceErr) {
			return nil, sourceErr
		}
		if _, err := os.Lstat(previous); err == nil {
			info, err := os.Lstat(previous)
			if err != nil || !info.IsDir() {
				return nil, reject("Home backup changed; data was preserved")
			}
			identity, err := homeIdentity(previous)
			if err != nil || (len(state.SourceIdentity) != 0 && !slices.Equal(identity, state.SourceIdentity)) {
				return nil, reject("Home volume changed or is unavailable; data was preserved")
			}
			if err := homeCheckIdentity(state.Target, targetIdentity); err != nil {
				return nil, err
			}
			for _, u := range state.Users {
				if err := noLinks(u.New); err != nil {
					return nil, err
				}
				relative, _ := filepath.Rel(state.Target, u.New)
				identity, err := homeIdentity(filepath.Join(homePinnedPath(target), relative))
				if err != nil || (len(u.NewIdentity) != 0 && !slices.Equal(identity, u.NewIdentity)) {
					return nil, reject("Home volume changed or is unavailable; data was preserved")
				}
			}
			mounts, err := s.mounts(ctx)
			if err != nil {
				return nil, err
			}
			for _, m := range mounts {
				if childOf(m.Target, filepath.Join(state.Backup, "previous")) {
					return nil, reject("The backup home folder contains mounts; data was preserved")
				}
			}
			if err := os.RemoveAll(previous); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if backup != nil {
		expected, err := homeIdentity(homePinnedPath(backup))
		if err != nil {
			return nil, err
		}
		if err := homeCheckIdentity(state.Backup, expected); err != nil {
			return nil, err
		}
	}
	if entries, err := os.ReadDir(state.Backup); err == nil && len(entries) == 0 {
		if err := os.Remove(state.Backup); err != nil {
			return nil, err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if state.Nologin != "" {
		if raw, err := os.ReadFile(s.nologin); err == nil && string(raw) == state.Nologin {
			if owned, err := homeFileMatches(s.nologin, state.NologinIdentity); err != nil {
				return nil, err
			} else if owned {
				if err := os.Remove(s.nologin); err != nil {
					return nil, err
				}
			}
		} else if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	if err := os.Remove(s.journal); err != nil {
		return nil, err
	}
	return marshal(map[string]any{"message": "Home move recovered. Any destination copy was retained."})
}

func RecoverHomes(ctx context.Context) error {
	s := defaultHomes()
	unlock, err := s.locked()
	if err != nil {
		return err
	}
	defer unlock()
	_, err = s.recover(ctx, nil)
	return err
}
