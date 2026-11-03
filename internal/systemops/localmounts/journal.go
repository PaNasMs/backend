package localmounts

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"panasms.local/backend/internal/systemops/storagebase"
	"path/filepath"
	"syscall"
)

type operationStep struct {
	Name      string `json:"name"`
	Completed bool   `json:"completed"`
}
type transaction struct {
	storagebase.TransactionEnvelope
	Fingerprint  string          `json:"fingerprint"`
	Point        string          `json:"point,omitempty"`
	FSType       string          `json:"fstype,omitempty"`
	FstabBefore  string          `json:"fstabBefore"`
	FstabDesired string          `json:"fstabDesired"`
	Stage        string          `json:"stage,omitempty"`
	StageIntent  bool            `json:"stageIntent,omitempty"`
	MountID      uint64          `json:"mountID,omitempty"`
	Steps        []operationStep `json:"steps"`
}

func journalPath(root, target string) string {
	return filepath.Join(root, storagebase.Hash(target)+".json")
}
func readJournal(root, target string, owner int) (*transaction, string, error) {
	if err := storagebase.SecureDirectory(root, owner, false); err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil
		}
		return nil, "", err
	}
	fd, err := unix.Open(journalPath(root, target), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	raw := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || int(raw.Uid) != owner || raw.Nlink != 1 {
		return nil, "", reject("Storage transaction permissions are unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > 2<<20 {
		return nil, "", reject("Storage transaction evidence is too large")
	}
	var state transaction
	if err = json.Unmarshal(data, &state); err != nil {
		return nil, "", err
	}
	if state.Schema != 1 || state.Domain != "localmounts" || state.Target != target || !IsAction(state.Action) || (state.Phase != "pending" && state.Phase != "complete") || state.Identity.BootID == "" || len(state.Identity.Devices) == 0 {
		return nil, "", reject("Storage transaction evidence is invalid")
	}
	return &state, storagebase.Hash(string(data)), nil
}
func writeJournal(root string, owner int, state *transaction) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return reject("Storage transaction evidence is too large")
	}
	if err = storagebase.SecureDirectory(root, owner, true); err != nil {
		return err
	}
	if _, _, err = readJournal(root, state.Target, owner); err != nil {
		return err
	}
	f, err := os.CreateTemp(root, ".journal-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, journalPath(root, state.Target)); err != nil {
		return err
	}
	return syncDirectory(root)
}
func syncDirectory(root string) error {
	f, err := os.Open(root)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func archiveJournal(root, target, expected string, owner int) error {
	prior, revision, err := readJournal(root, target, owner)
	if err != nil {
		return err
	}
	if prior == nil {
		if expected != "" {
			return reject("Storage recovery evidence changed")
		}
		return nil
	}
	if revision != expected {
		return reject("Storage recovery evidence changed")
	}
	source := journalPath(root, target)
	destination := source + ".history-" + revision
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if storagebase.Hash(string(data)) != revision {
		return reject("Storage recovery evidence changed")
	}
	f, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil && !os.IsExist(err) {
		return err
	}
	if err == nil {
		if _, err = f.Write(data); err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	historical, err := os.ReadFile(destination)
	if err != nil {
		return err
	}
	if storagebase.Hash(string(historical)) != revision {
		return fmt.Errorf("storage history collision")
	}
	// Keep the old active record until the replacement intent is durable.
	return syncDirectory(root)
}
func step(state *transaction, name string, save func(*transaction) error, operation func() error) error {
	state.Steps = append(state.Steps, operationStep{Name: name})
	if err := save(state); err != nil {
		return err
	}
	if err := operation(); err != nil {
		return err
	}
	state.Steps[len(state.Steps)-1].Completed = true
	return save(state)
}
