package modulelifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

var sourceAddID = regexp.MustCompile("^[0-9a-f]{32}$")

const sourceAddSlot = "config"

type sourceAddFile struct {
	Device, Inode uint64
	Mode, Group   uint32
	Digest        string
}

type sourceAddStage struct {
	ID            string
	Directory     directoryIdentity
	Before, After sourceAddFile
	Owner         uint32
}

func sourceAddFileAt(dir *os.File, name string, owner uint32) (sourceAddFile, []byte, error) {
	raw, st, err := readOwnedSnapshotAt(dir, name, owner, maxSourceState)
	if errors.Is(err, unix.ENOENT) {
		return sourceAddFile{}, nil, nil
	}
	if err != nil {
		return sourceAddFile{}, nil, err
	}
	return sourceAddFile{uint64(st.Dev), st.Ino, st.Mode, st.Gid, sourceDigest(raw)}, raw, nil
}

func (s sourceAddStage) name() string { return ".source-add-" + s.ID }

func (s sourceAddStage) open(config *os.File) (*os.File, error) {
	if !sourceAddID.MatchString(s.ID) {
		return nil, reject("Invalid source add stage")
	}
	fd, err := unix.Openat(int(config.Fd()), s.name(), unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil && (st.Mode != unix.S_IFDIR|0700 || st.Uid != s.Owner ||
		!s.Directory.Exists || s.Directory.Device != uint64(st.Dev) || s.Directory.Inode != st.Ino) {
		err = unix.ESTALE
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), s.name()), nil
}

func (c catalogService) prepareSourceAdd(config *os.File, id string, next []byte) (sourceAddStage, error) {
	stage := sourceAddStage{ID: id, Owner: c.owner}
	if !sourceAddID.MatchString(id) || len(next) > maxSourceState {
		return stage, reject("Invalid source add stage")
	}
	prior, raw, err := sourceAddFileAt(config, filepath.Base(c.config), c.owner)
	if err != nil {
		return stage, err
	}
	stage.Before = prior
	var rows []map[string]any
	if prior.Inode == 0 {
		rows = []map[string]any{officialSource()}
	} else if systemops.Decode(raw, &rows) != nil {
		return stage, reject("Invalid module repository configuration")
	}
	var after []map[string]any
	if systemops.Decode(next, &after) != nil || len(after) == 0 || sourceState(rows) != sourceState(after[:len(after)-1]) {
		return stage, reject("Module repository configuration changed before staging")
	}
	if err = unix.Mkdirat(int(config.Fd()), stage.name(), 0700); err != nil {
		return stage, err
	}
	stage.Directory, err = directoryAt(config, stage.name(), c.owner)
	if err != nil {
		return stage, err
	}
	dir, err := stage.open(config)
	if err != nil {
		return stage, err
	}
	defer dir.Close()
	err = atomicWriteAt(dir, sourceAddSlot, next, 0600, c.owner, uint32(os.Getegid()), true)
	if err == nil {
		stage.After, _, err = sourceAddFileAt(dir, sourceAddSlot, c.owner)
	}
	if err == nil {
		err = config.Sync()
	}
	if err != nil {
		return stage, errors.Join(err, stage.cleanup(config))
	}
	return stage, nil
}

func (s sourceAddStage) publish(config *os.File, target string) (bool, error) {
	dir, err := s.open(config)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	live, _, err := sourceAddFileAt(config, target, s.Owner)
	if err != nil {
		return false, err
	}
	draft, _, err := sourceAddFileAt(dir, sourceAddSlot, s.Owner)
	if err != nil {
		return false, err
	}
	if s.After.Inode == 0 || draft != s.After || live != s.Before {
		return false, reject("Module repository configuration changed before publication")
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if s.Before.Inode != 0 {
		flags = unix.RENAME_EXCHANGE
	}
	if err := unix.Renameat2(int(dir.Fd()), sourceAddSlot, int(config.Fd()), target, flags); err != nil {
		return false, err
	}
	return true, errors.Join(dir.Sync(), config.Sync())
}

// The private slot witnesses the rename even if an administrator later replaces
// the public configuration. The original inode moves here on exchange; a
// no-replace rename into an absent destination consumes the slot.
func (s sourceAddStage) committed(config *os.File) (bool, error) {
	dir, err := s.open(config)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	if err := errors.Join(dir.Sync(), config.Sync()); err != nil {
		return false, err
	}
	var slot unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), sourceAddSlot, &slot, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return s.Before.Inode == 0 && s.After.Inode != 0, nil
	}
	return err == nil && s.Before.Inode != 0 && s.Before.Device == uint64(slot.Dev) && s.Before.Inode == slot.Ino, err
}

func (s sourceAddStage) cleanup(config *os.File) error {
	dir, err := s.open(config)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return config.Sync()
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	slot, _, err := sourceAddFileAt(dir, sourceAddSlot, s.Owner)
	var foreign *systemops.Rejected
	if errors.As(err, &foreign) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENXIO) {
		return nil
	}
	if err != nil {
		return err
	}
	if slot.Inode != 0 {
		if slot != s.Before && slot != s.After {
			return nil
		}
		if err = unlinkCatalogFile(dir, sourceAddSlot); err != nil {
			return err
		}
	}
	current, err := directoryAt(config, s.name(), s.Owner)
	if err != nil || current != s.Directory {
		return err
	}
	err = unix.Unlinkat(int(config.Fd()), s.name(), unix.AT_REMOVEDIR)
	if err != nil && !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return config.Sync()
}
