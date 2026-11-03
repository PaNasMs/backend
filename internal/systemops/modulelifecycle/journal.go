package modulelifecycle

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type fileSnapshot struct {
	Exists bool   `json:"exists"`
	Data   []byte `json:"data,omitempty"`
	Mode   uint32 `json:"mode,omitempty"`
	UID    uint32 `json:"uid,omitempty"`
	GID    uint32 `json:"gid,omitempty"`
}

type directoryIdentity struct {
	Exists bool   `json:"exists"`
	Device uint64 `json:"device,omitempty"`
	Inode  uint64 `json:"inode,omitempty"`
}

type payloadState struct {
	Before directoryIdentity `json:"before"`
	Staged directoryIdentity `json:"staged"`
}

// The original fields remain readable by the retained Python recovery code.
type transaction struct {
	Before            Registry                `json:"before"`
	Affected          []string                `json:"affected"`
	Committed         bool                    `json:"committed"`
	Schema            int                     `json:"schema,omitempty"`
	Phase             string                  `json:"phase,omitempty"`
	Units             map[string]fileSnapshot `json:"units,omitempty"`
	Payloads          map[string]payloadState `json:"payloads,omitempty"`
	After             Registry                `json:"after,omitempty"`
	Candidates        map[string]fileSnapshot `json:"unitCandidates,omitempty"`
	orphan            bool
	orphanFingerprint string
}

func (state *transaction) requiresBarrier() bool {
	return !state.orphan && !state.Committed && (state.Schema == 0 || state.Phase == "switching")
}

func (s store) transactionDirectory() (*os.File, error) {
	root, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	fd, err := unix.Openat(int(root.Fd()), ".transaction", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Uid != s.owner || stat.Mode&0777 != 0700 {
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		return nil, reject("Module transaction permissions are unsafe")
	}
	return os.NewFile(uintptr(fd), "module transaction"), nil
}

func (s store) loadTransaction() (*transaction, error) {
	directory, err := s.transactionDirectory()
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	raw, err := readOwnedAt(directory, "journal.json", s.owner, 16<<20)
	if errors.Is(err, unix.ENOENT) {
		return orphanTransaction(directory, s.owner)
	}
	if err != nil {
		return nil, err
	}
	var state transaction
	if systemops.Decode(raw, &state) != nil || state.validate(s.owner) != nil {
		return nil, reject("Module recovery journal is invalid; recorded files were preserved")
	}
	return &state, nil
}

func (state *transaction) validate(owner uint32) error {
	if state.Before == nil || len(state.Affected) > 6000 || state.Schema < 0 || state.Schema > 1 || state.Schema == 1 && len(state.Affected) == 0 {
		return reject("Invalid module transaction")
	}
	raw, err := json.Marshal(state.Before)
	if err != nil {
		return err
	}
	if _, err = decodeRegistry(raw); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, id := range state.Affected {
		if identifier(id) != nil || seen[id] {
			return reject("Invalid module transaction")
		}
		seen[id] = true
	}
	if state.Schema == 0 {
		if state.Phase != "" || state.Units != nil || state.Payloads != nil || state.After != nil || state.Candidates != nil {
			return reject("Invalid legacy module transaction")
		}
		return nil
	}
	if state.Phase != "staging" && state.Phase != "switching" {
		return reject("Invalid module transaction phase")
	}
	if state.Committed && state.Phase != "switching" {
		return reject("Invalid module transaction commit")
	}
	if state.After == nil || len(state.Units) != len(seen) || len(state.Payloads) != len(seen) || len(state.Candidates) != len(seen) {
		return reject("Incomplete module transaction")
	}
	raw, err = json.Marshal(state.After)
	if err != nil {
		return err
	}
	if _, err = decodeRegistry(raw); err != nil {
		return err
	}
	for id := range seen {
		_, exists := state.Units[id]
		payload, payloadExists := state.Payloads[id]
		_, candidateExists := state.Candidates[id]
		if !exists || !payloadExists || !candidateExists {
			return reject("Invalid module transaction ownership")
		}
		for _, unit := range []fileSnapshot{state.Units[id], state.Candidates[id]} {
			if len(unit.Data) > 65536 || unit.Exists && (unit.UID != owner || unit.Mode&0022 != 0 || unit.Mode&^0777 != 0) {
				return reject("Invalid module transaction ownership")
			}
			if !unit.Exists && (len(unit.Data) != 0 || unit.Mode != 0 || unit.UID != 0 || unit.GID != 0) {
				return reject("Invalid absent module unit")
			}
		}
		for _, identity := range []directoryIdentity{payload.Before, payload.Staged} {
			if identity.Exists && identity.Inode == 0 || !identity.Exists && (identity.Device != 0 || identity.Inode != 0) {
				return reject("Invalid module payload identity")
			}
		}
	}
	return nil
}

func (s store) saveTransaction(state *transaction) error {
	if state.orphan {
		return reject("An orphan module transaction cannot be rewritten")
	}
	if err := state.validate(s.owner); err != nil {
		return err
	}
	directory, err := s.transactionDirectory()
	if err != nil {
		return err
	}
	defer directory.Close()
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicAt(directory, "journal.json", raw, 0600, s.owner)
}

func snapshotAt(directory *os.File, name string, owner uint32) (fileSnapshot, error) {
	raw, stat, err := readOwnedSnapshotAt(directory, name, owner, 65536)
	if errors.Is(err, unix.ENOENT) {
		return fileSnapshot{}, nil
	}
	if err != nil {
		return fileSnapshot{}, err
	}
	return fileSnapshot{Exists: true, Data: raw, Mode: stat.Mode & 0777, UID: stat.Uid, GID: stat.Gid}, nil
}

func directoryAt(parent *os.File, name string, owner uint32) (directoryIdentity, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return directoryIdentity{}, reject("Invalid module state path")
	}
	var stat unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return directoryIdentity{}, nil
	}
	if err != nil {
		return directoryIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner || stat.Mode&0022 != 0 {
		return directoryIdentity{}, reject("Module payload permissions are unsafe")
	}
	return directoryIdentity{Exists: true, Device: uint64(stat.Dev), Inode: stat.Ino}, nil
}
