package modulelifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

var sourceAddID = regexp.MustCompile("^[0-9a-f]{32}$")

const sourceAddStageRoot = ".panasms-source-staging"

type sourceAddFile struct {
	Inode       uint64
	Mode, Group uint32
	Digest      string
}

type sourceAddStage struct {
	ID            string
	Directory     uint64
	Before, After sourceAddFile
	Owner         uint32
	SeenVacant    bool `json:",omitempty"`
	NamedVacant   bool `json:",omitempty"`
	Writing       bool `json:",omitempty"`
	displaced     *unix.Stat_t
}

func sourceAddFileAt(dir *os.File, name string, owner uint32) (sourceAddFile, []byte, error) {
	raw, st, err := readOwnedSnapshotAt(dir, name, owner, maxSourceState)
	if errors.Is(err, unix.ENOENT) {
		return sourceAddFile{}, nil, nil
	}
	if err != nil {
		return sourceAddFile{}, nil, err
	}
	return sourceAddFile{st.Ino, st.Mode, st.Gid, sourceDigest(raw)}, raw, nil
}

func (s sourceAddStage) open(config *os.File) (*os.File, error) {
	if !sourceAddID.MatchString(s.ID) {
		return nil, reject("Invalid source add stage")
	}
	fd, err := unix.Openat(int(config.Fd()), sourceAddStageRoot, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil && (st.Mode&(unix.S_IFMT|0777) != unix.S_IFDIR|0700 || st.Uid != s.Owner ||
		s.Directory == 0 || s.Directory != st.Ino) {
		err = unix.ESTALE
	}
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), sourceAddStageRoot), nil
}

func (c catalogService) prepareSourceAdd(config *os.File, id string, next []byte, register func(sourceAddStage) error) (sourceAddStage, error) {
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
	stage, err = stage.writeDraftWithBoundary(config, next, 0600, register, c.draftBoundary)
	if err == nil && c.sourceBoundary != nil {
		err = c.sourceBoundary("draft-linked")
	}
	return stage, err
}

func (stage sourceAddStage) writeDraft(parentDir *os.File, next []byte, mode uint32, register func(sourceAddStage) error) (sourceAddStage, error) {
	return stage.writeDraftWithBoundary(parentDir, next, mode, register, nil)
}

func (stage sourceAddStage) writeDraftWithBoundary(parentDir *os.File, next []byte, mode uint32, register func(sourceAddStage) error, boundary func(string, *os.File, []byte) error) (sourceAddStage, error) {
	if !sourceAddID.MatchString(stage.ID) {
		return stage, reject("Invalid source add stage")
	}
	dir, err := createDirectoryAt(parentDir, sourceAddStageRoot, 0700, stage.Owner, false)
	if err != nil {
		return stage, err
	}
	defer dir.Close()
	var parent, private unix.Stat_t
	if err := unix.Fstat(int(parentDir.Fd()), &parent); err != nil {
		return stage, err
	}
	if err := unix.Fstat(int(dir.Fd()), &private); err != nil {
		return stage, err
	}
	if private.Mode&0777 != 0700 || private.Dev != parent.Dev {
		return stage, reject("Repository staging requires a private directory on the same filesystem")
	}
	stage.Directory = private.Ino
	stage.Writing = true
	if err := parentDir.Sync(); err != nil {
		return stage, err
	}
	if err := register(stage); err != nil {
		return stage, err
	}
	dirFD := int(dir.Fd())
	var fd int
	if boundary != nil {
		err = boundary("open-anonymous", nil, nil)
	}
	if err == nil {
		fd, err = unix.Openat(dirFD, ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, mode)
	}
	anonymous := err == nil
	if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.EINVAL) {
		// The helper is the sole writer in this private namespace. Record that
		// this name was vacant before allocating even an empty fallback file.
		var st unix.Stat_t
		lookupErr := unix.Fstatat(dirFD, stage.ID, &st, unix.AT_SYMLINK_NOFOLLOW)
		if lookupErr == nil {
			return stage, unix.EEXIST
		}
		if !errors.Is(lookupErr, unix.ENOENT) {
			return stage, lookupErr
		}
		stage.NamedVacant = true
		if err := register(stage); err != nil {
			return stage, err
		}
		fd, err = unix.Openat(dirFD, stage.ID, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	}
	if err != nil {
		return stage, err
	}
	file := os.NewFile(uintptr(fd), stage.ID)
	defer file.Close()
	if !anonymous && boundary != nil {
		if err := boundary("named-draft-allocated", file, nil); err != nil {
			return stage, err
		}
	}
	var created unix.Stat_t
	if err := file.Chmod(os.FileMode(mode)); err != nil {
		return stage, err
	}
	if err := unix.Fstat(fd, &created); err != nil {
		return stage, err
	}
	if created.Uid != stage.Owner || created.Mode&0777 != mode {
		return stage, reject("Invalid source draft permissions")
	}
	stage.After = sourceAddFile{created.Ino, created.Mode, created.Gid, sourceDigest(next)}
	if err := register(stage); err != nil {
		return stage, err
	}
	if !anonymous && boundary != nil {
		if err := boundary("named-draft-writing", file, next); err != nil {
			return stage, err
		}
	}
	if _, err := file.Write(next); err != nil {
		return stage, err
	}
	if err := file.Sync(); err != nil {
		return stage, err
	}
	if anonymous {
		err = unix.Linkat(fd, "", dirFD, stage.ID, unix.AT_EMPTY_PATH)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPERM) {
			err = unix.Linkat(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(fd), dirFD, stage.ID, unix.AT_SYMLINK_FOLLOW)
		}
		if err != nil {
			return stage, err
		}
	}
	if err := dir.Sync(); err != nil {
		return stage, err
	}
	stage.Writing = false
	return stage, nil
}

func (s sourceAddStage) publishKey(parent *os.File, target string, boundary func(string) error) error {
	dir, err := s.open(parent)
	if errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) {
		return errSourceAddFenced
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	// On retry, make either side of the previous rename durable before
	// interpreting a missing private slot as a completed publication.
	if err := errors.Join(dir.Sync(), parent.Sync()); err != nil {
		return err
	}
	draft, _, err := sourceAddFileAt(dir, s.ID, s.Owner)
	var rejected *systemops.Rejected
	if errors.As(err, &rejected) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENXIO) {
		return errSourceAddFenced
	}
	if err != nil {
		return err
	}
	if draft.Inode == 0 {
		return unix.ENOENT
	}
	if draft != s.After {
		return errSourceAddFenced
	}
	if boundary != nil {
		err = boundary("key-rename")
	}
	if err == nil {
		err = unix.Renameat2(int(dir.Fd()), s.ID, int(parent.Fd()), target, unix.RENAME_NOREPLACE)
	}
	if errors.Is(err, unix.EXDEV) {
		return errSourceAddFenced
	}
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), parent.Sync())
}

func (s *sourceAddStage) publish(config *os.File, target string) (bool, error) {
	dir, err := s.open(config)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	live, _, err := sourceAddFileAt(config, target, s.Owner)
	if err != nil {
		return false, err
	}
	draft, _, err := sourceAddFileAt(dir, s.ID, s.Owner)
	if err != nil {
		return false, err
	}
	if s.After.Inode == 0 || s.Before.Inode == s.After.Inode || draft != s.After || live != s.Before {
		return false, reject("Module repository configuration changed before publication")
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if s.Before.Inode != 0 {
		flags = unix.RENAME_EXCHANGE
	}
	if err := unix.Renameat2(int(dir.Fd()), s.ID, int(config.Fd()), target, flags); err != nil {
		return false, err
	}
	if s.Before.Inode != 0 {
		var displaced unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), s.ID, &displaced, unix.AT_SYMLINK_NOFOLLOW); err == nil && displaced.Ino == s.Before.Inode {
			s.displaced = &displaced
		}
	}
	return true, errors.Join(dir.Sync(), config.Sync())
}

// The private slot witnesses the rename even if an administrator later replaces
// the public configuration. The original inode moves here on exchange; a
// no-replace rename into an absent destination consumes the slot.
func (s sourceAddStage) committed(config *os.File) (bool, error) {
	dir, err := s.open(config)
	if errors.Is(err, unix.ESTALE) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer dir.Close()
	if err := errors.Join(dir.Sync(), config.Sync()); err != nil {
		return false, err
	}
	var slot unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), s.ID, &slot, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	if s.After.Inode == 0 || s.Before.Inode == s.After.Inode {
		return false, nil
	}
	if s.Before.Inode == 0 {
		return errors.Is(err, unix.ENOENT), nil
	}
	// An editor can retain a descriptor to the displaced config across the
	// exchange. Its inode proves the rename even after a later edit or chmod.
	return err == nil && slot.Ino == s.Before.Inode, nil
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
	// An open descriptor can still change the old public config after exchange.
	// Only the publishing helper witnessed its post-rename timestamps. On
	// restart, retain that inode for reconciliation without touching its atime.
	if s.Before.Inode != 0 && s.Before.Inode != s.After.Inode {
		var live unix.Stat_t
		err := unix.Fstatat(int(dir.Fd()), s.ID, &live, unix.AT_SYMLINK_NOFOLLOW)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		if err == nil && live.Ino == s.Before.Inode && (s.displaced == nil ||
			live.Ctim != s.displaced.Ctim || live.Mtim != s.displaced.Mtim || live.Atim != s.displaced.Atim) {
			return dir.Sync()
		}
	}
	slot, _, err := sourceAddFileAt(dir, s.ID, s.Owner)
	var foreign *systemops.Rejected
	if errors.As(err, &foreign) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENXIO) {
		return nil
	}
	if err != nil {
		return err
	}
	if slot.Inode != 0 {
		// A named draft can be interrupted during its first write on
		// filesystems without O_TMPFILE. Its inode was journaled before writing.
		ownedPartial := s.Writing && slot.Inode == s.After.Inode && slot.Mode == s.After.Mode && slot.Group == s.After.Group
		ownedEmpty := s.Writing && s.NamedVacant && s.After.Inode == 0 && slot.Digest == sourceDigest(nil)
		if slot != s.Before && slot != s.After && !ownedPartial && !ownedEmpty {
			return nil
		}
		if err = unlinkCatalogFile(dir, s.ID); err != nil {
			return err
		}
	}
	return dir.Sync()
}
