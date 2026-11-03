package partitionfs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

type step struct {
	Name      string `json:"name"`
	Completed bool   `json:"completed"`
}
type transaction struct {
	Domain       string                       `json:"domain"`
	Phase        string                       `json:"phase"`
	Schema       int                          `json:"schema"`
	Action       string                       `json:"action"`
	Target       string                       `json:"target"`
	Fingerprint  string                       `json:"fingerprint"`
	Identity     storagequery.StorageIdentity `json:"identity"`
	Steps        []step                       `json:"steps"`
	Complete     bool                         `json:"complete"`
	FstabBefore  string                       `json:"fstabBefore"`
	FstabDesired string                       `json:"fstabDesired"`
}

func journalKey(target string) string {
	sum := sha256.Sum256([]byte(target))
	return hex.EncodeToString(sum[:])
}
func (s *service) journalPath(target string) string {
	return filepath.Join(s.root, journalKey(target)+".json")
}
func (s *service) load(target string) (*transaction, error) {
	if err := storagebase.SecureDirectory(s.root, s.owner, false); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	fd, err := unix.Open(s.journalPath(target), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	raw := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || int(raw.Uid) != s.owner || raw.Nlink != 1 {
		return nil, reject("Storage recovery record permissions are unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(f, 2*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 2*1024*1024 {
		return nil, reject("Storage recovery record is invalid")
	}
	var state transaction
	if err = systemops.Decode(data, &state); err != nil || state.Schema != 1 || state.Domain != "partitionfs" || (state.Phase != "pending" && state.Phase != "complete") || (state.Complete != (state.Phase == "complete")) || state.Target != target || !IsAction(state.Action) || len(state.Fingerprint) != 64 || state.Identity.BootID == "" || len(state.Identity.Devices) == 0 {
		return nil, reject("Storage recovery record is invalid")
	}
	return &state, nil
}
func (s *service) save(state *transaction) error {
	if err := storagebase.SecureDirectory(s.root, s.owner, true); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.write(s.journalPath(state.Target), string(data), 0600)
}
func (s *service) archive(state *transaction) error {
	if state == nil {
		return nil
	}
	path := s.journalPath(state.Target)
	// An existing reviewed record is retained, never silently replayed or deleted.
	history, err := os.CreateTemp(s.root, journalKey(state.Target)+".history-*")
	if err != nil {
		return err
	}
	name := history.Name()
	if err = history.Close(); err != nil {
		return err
	}
	if err = os.Rename(path, name); err != nil {
		return err
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func hardwareEqual(a, b storagequery.StorageIdentity) bool {
	if a.BootID != b.BootID || len(a.Devices) != len(b.Devices) {
		return false
	}
	for i, x := range a.Devices {
		y := b.Devices[i]
		if x.Path != y.Path || x.DeviceNumber != y.DeviceNumber || x.DiskSequence != y.DiskSequence || x.WWN != y.WWN || x.Serial != y.Serial {
			return false
		}
	}
	return true
}
func Recovery(target string) (json.RawMessage, error) {
	if !strings.HasPrefix(target, "/dev/") || filepath.Clean(target) != target {
		return nil, reject("Select a block device")
	}
	s := defaultService()
	state, err := s.load(target)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"target": target, "journal": state, "automaticReplay": false, "message": "Inspect the current partition table and file system before preparing another operation. Interrupted writes are never repeated automatically."})
}
