package accounts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const sharingLegacyDrift = "Legacy NFS configuration was edited outside the panel. Review and restore the saved file before continuing."

type sharingFileSnapshot struct {
	Exists bool
	Data   []byte
	Mode   uint32
	UID    uint32
	GID    uint32
}

func (entry sharingFileSnapshot) MarshalJSON() ([]byte, error) {
	if !entry.Exists {
		return []byte(`{"exists":false}`), nil
	}
	return json.Marshal(struct {
		Exists bool   `json:"exists"`
		Data   []byte `json:"data"`
		Mode   uint32 `json:"mode"`
		UID    uint32 `json:"uid"`
		GID    uint32 `json:"gid"`
	}{true, entry.Data, entry.Mode, entry.UID, entry.GID})
}

func (s *sharingService) secureParents(path string) error {
	root := s.secureRoot
	if root == "" {
		root = "/"
	}
	if !childOf(path, root) {
		return reject(sharingConfigurationUntrusted)
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		var stat unix.Stat_t
		err := unix.Lstat(parent, &stat)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			if stat.Mode&unix.S_IFMT != unix.S_IFDIR || int(stat.Uid) != s.ownerUID || stat.Mode&0022 != 0 {
				return reject(sharingConfigurationUntrusted)
			}
		}
		if parent == root {
			return nil
		}
	}
}

func (s *sharingService) fileSnapshot(path string) (sharingFileSnapshot, error) {
	var entry sharingFileSnapshot
	if err := s.secureParents(path); err != nil {
		return entry, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return entry, nil
	}
	if err != nil {
		return entry, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return entry, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || int(stat.Uid) != s.ownerUID || stat.Mode&0022 != 0 {
		return entry, reject(sharingConfigurationUntrusted)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return entry, err
	}
	return sharingFileSnapshot{true, data, stat.Mode & 0777, stat.Uid, stat.Gid}, nil
}

func sharingSnapshotRevision(entry sharingFileSnapshot) string {
	raw, _ := json.Marshal(entry)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *sharingService) legacyRevision() (string, error) {
	entry, err := s.fileSnapshot(s.legacy)
	if err != nil {
		return "", err
	}
	return sharingSnapshotRevision(entry), nil
}

func (s *sharingService) validateLegacyRevision(st sharingState) error {
	revision, err := s.legacyRevision()
	if err != nil {
		return err
	}
	if st.LegacyExportRevision == "" || revision != st.LegacyExportRevision {
		return reject(sharingLegacyDrift)
	}
	return nil
}

func (s *sharingService) rollbackWitness(ctx context.Context) (map[string]any, error) {
	if err := s.authorizeNative(ctx, "rollback-check"); err != nil {
		return nil, err
	}
	if err := s.secureParents(s.lock); err != nil {
		return nil, err
	}
	fd, err := unix.Open(s.lock, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || int(stat.Uid) != s.ownerUID || stat.Mode&0022 != 0 {
		return nil, reject(sharingConfigurationUntrusted)
	}
	if err = unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB); err != nil {
		return nil, reject("A sharing operation is already in progress")
	}
	if err = s.authorizeNative(ctx, "rollback-check"); err != nil {
		return nil, err
	}
	return s.rollbackWitnessLocked()
}

func (s *sharingService) rollbackWitnessLocked() (map[string]any, error) {
	for _, path := range []string{s.journal, filepath.Join(filepath.Dir(s.journal), "sharing-legacy-nfs-transaction.json")} {
		if pending, err := sharingExists(path); err != nil || pending {
			return nil, reject(sharingPending)
		}
	}
	files := map[string]sharingFileSnapshot{}
	for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
		entry, err := s.fileSnapshot(path)
		if err != nil {
			return nil, err
		}
		files[path] = entry
	}
	if s.pendingRollback {
		var ticket sharingActivationTicket
		if present, err := s.metadata(s.activationTicket, &ticket); err != nil || !present || s.validTicket(&ticket) != nil {
			return nil, reject(sharingActivationPending)
		}
		validated, err := s.pendingActivationFiles(ticket)
		if err != nil {
			return nil, err
		}
		return map[string]any{"schema": 1, "files": validated, "journalsAbsent": true}, nil
	}
	if s.rollbackSource != nil {
		source, err := sharingAccountSnapshot(s.rollbackSource[s.state])
		if err != nil {
			return nil, err
		}
		current, err := sharingAccountSnapshot(files[s.state])
		if err != nil {
			return nil, err
		}
		if string(source) != string(current) {
			return nil, reject("SMB account access needs recovery before rollback can continue.")
		}
	}
	st := sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}}
	if files[s.state].Exists {
		if err := systemops.Decode(files[s.state].Data, &st); err != nil {
			return nil, err
		}
	}
	if err := validateSharingState(st); err != nil {
		return nil, err
	}
	if st.LegacyExportRevision == "" || st.LegacyExportRevision != sharingSnapshotRevision(files[s.legacy]) {
		return nil, reject(sharingLegacyDrift)
	}
	if !s.knownSharingConfig(files, st) {
		return nil, reject(sharingDrift)
	}
	return map[string]any{"schema": 1, "files": files, "journalsAbsent": true}, nil
}

func sharingSnapshotsEqual(a, b sharingFileSnapshot) bool {
	return a.Exists == b.Exists && (!a.Exists || string(a.Data) == string(b.Data) && a.Mode == b.Mode && a.UID == b.UID && a.GID == b.GID)
}

func (s *sharingService) writeHookConversion(before sharingFileSnapshot, text string) error {
	if !before.Exists {
		return reject(sharingDrift)
	}
	file, err := os.CreateTemp(filepath.Dir(s.smb), ".panasms-hook-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chown(int(before.UID), int(before.GID)); err != nil {
		return err
	}
	if err = file.Chmod(os.FileMode(before.Mode)); err != nil {
		return err
	}
	if _, err = file.WriteString(text); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	current, err := s.fileSnapshot(s.smb)
	if err != nil {
		return err
	}
	if !sharingSnapshotsEqual(current, before) {
		return reject(sharingDrift)
	}
	if err = os.Rename(file.Name(), s.smb); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.smb))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func sharingAccountSnapshot(entry sharingFileSnapshot) ([]byte, error) {
	accounts := map[string]any{}
	if entry.Exists {
		var state map[string]json.RawMessage
		if err := systemops.Decode(entry.Data, &state); err != nil {
			return nil, err
		}
		if raw, ok := state["accounts"]; ok {
			if err := systemops.Decode(raw, &accounts); err != nil {
				return nil, err
			}
		}
	}
	if accounts == nil {
		accounts = map[string]any{}
	}
	return json.Marshal(accounts)
}

func (s *sharingService) knownSharingConfig(files map[string]sharingFileSnapshot, st sharingState) bool {
	for _, python := range []bool{false, true} {
		for _, legacy := range []bool{false, true} {
			smb, nfs := sharingConfig(st.Shares, python, legacy)
			if (string(files[s.smb].Data) == smb || !files[s.smb].Exists && len(st.Shares) == 0) && (string(files[s.exports].Data) == nfs || !files[s.exports].Exists && len(st.Shares) == 0) {
				return true
			}
		}
	}
	return false
}
