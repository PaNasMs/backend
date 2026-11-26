package modulelifecycle

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const sourceStagePrefix = ".module-sources.swap-"

var exchangeSource = func(fd int, stage string) error {
	return unix.Renameat2(fd, stage, fd, sourceFile, unix.RENAME_EXCHANGE)
}

// The module lock excludes other transactions, but not editors. Exchange the
// draft rather than replacing the live inode: a save between our last read
// and rename must remain named. The stage name records enough to check which
// side of the exchange survived a crash, without a second journal update.
func (s lifecycle) publishSources(dir *os.File, before []byte, existed bool, raw []byte) error {
	fd := int(dir.Fd())
	return writeOwnedAt(dir, sourceFile, raw, 0600, s.owner, uint32(os.Getegid()), func(draft string, ino uint64) error {
		stage := ""
		if existed {
			live, err := readOwnedAt(dir, sourceFile, s.owner, 1<<20)
			if err != nil {
				return err
			}
			if !bytes.Equal(live, before) {
				return reject("Repository configuration changed during commit; current files were preserved")
			}
			stage = fmt.Sprintf("%s%d-%x", sourceStagePrefix, ino, sha256.Sum256(before))
			if err := unix.Renameat2(fd, draft, fd, stage, unix.RENAME_NOREPLACE); err != nil {
				return err
			}
			if err := exchangeSource(fd, stage); err != nil {
				return err
			}
		} else if err := unix.Renameat2(fd, draft, fd, sourceFile, unix.RENAME_NOREPLACE); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return reject("Repository configuration appeared during commit; current files were preserved")
			}
			return err
		}
		if err := syncDir(dir); err != nil {
			return &renamedSyncError{err}
		}
		if stage != "" {
			return s.finishSourceStage(dir, stage)
		}
		return nil
	})
}

func (s lifecycle) finishSourceStages(dir *os.File) error {
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, sourceStagePrefix) {
			if err := s.finishSourceStage(dir, name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s lifecycle) finishSourceStage(dir *os.File, name string) error {
	inode, digest, ok := strings.Cut(strings.TrimPrefix(name, sourceStagePrefix), "-")
	ino, e := strconv.ParseUint(inode, 10, 64)
	if !ok || e != nil || len(digest) != 64 {
		return reject("Invalid repository configuration stage")
	}
	raw, stat, err := readOwnedSnapshotAt(dir, name, s.owner, 1<<20)
	if err != nil {
		return err
	}
	fd := int(dir.Fd())
	// Only an unpublished draft can be unlinked.
	if stat.Ino == ino {
		return unix.Unlinkat(fd, name, 0)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != digest {
		return reject("Repository configuration conflict: reconcile " + name + " with module-sources.json, then move the stage aside and retry recovery")
	}
	// Even unchanged bytes can belong to an editor holding a writable fd. Do
	// not unlink this inode. Administrators can prune previous versions once
	// their editors are closed.
	return unix.Renameat2(fd, name, fd, "module-sources.previous-"+rand.Text(), unix.RENAME_NOREPLACE)
}
