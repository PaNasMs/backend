package modulelifecycle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const writeClaimPrefix = ".source-add-write."
const writeClaimTag = "panasms-source-write-v1:"

func readWriteTag(dir *os.File, name string) (string, error) {
	var buf [128]byte
	n, err := unix.Readlinkat(int(dir.Fd()), name, buf[:])
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// Reserve a vacant name before creating even an empty file. Bind its inode
// before writing so recovery can recognize a partial write after process death.
func (c catalogService) writeSourceAddRecord(dir *os.File, target string, raw []byte, createOnly bool) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	id := hex.EncodeToString(nonce[:])
	claim := writeClaimPrefix + id
	tag := writeClaimTag + id
	fd := int(dir.Fd())
	for _, path := range []string{claim + ".data", claim + ".inode"} {
		var stat unix.Stat_t
		err := unix.Fstatat(fd, path, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return unix.EEXIST
		}
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	if err := unix.Symlinkat(tag, fd, claim); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	err := atomicWriteNamedAt(dir, target, raw, 0600, c.owner, uint32(os.Getegid()), createOnly, claim+".data", func(inode uint64) error {
		if err := unix.Symlinkat(tag+":"+strconv.FormatUint(inode, 10), fd, claim+".inode"); err != nil {
			return err
		}
		if err := dir.Sync(); err != nil {
			return err
		}
		if c.sourceBoundary != nil {
			if createOnly {
				return c.sourceBoundary("hold-scratch-created")
			}
			return c.sourceBoundary("journal-scratch-created")
		}
		return nil
	})
	return errors.Join(err, c.retireSourceAddWrite(dir, claim, tag))
}

func (c catalogService) retireSourceAddWrite(dir *os.File, claim, tag string) error {
	identity, err := readWriteTag(dir, claim+".inode")
	if err != nil {
		return err
	}
	number, tagged := strings.CutPrefix(identity, tag+":")
	inode, err := strconv.ParseUint(number, 10, 64)
	bound := tagged && err == nil && inode != 0 && strconv.FormatUint(inode, 10) == number
	var stat unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), claim+".data", &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err == nil && stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Uid == c.owner && stat.Nlink == 1 && stat.Mode&0022 == 0 &&
		(bound && stat.Ino == inode || identity == "" && stat.Size == 0) {
		if err := unlinkCatalogFile(dir, claim+".data"); err != nil {
			return err
		}
	}
	if bound {
		if err := unlinkCatalogFile(dir, claim+".inode"); err != nil {
			return err
		}
	}
	return unlinkCatalogFile(dir, claim)
}

func (c catalogService) recoverSourceAddWrites(ctx context.Context, dir *os.File, r *systemops.Reporter) error {
	names, err := sourceRecordNames(dir, writeClaimPrefix)
	if err != nil {
		return err
	}
	var lock *os.File
	for _, name := range names {
		tag, err := readWriteTag(dir, name)
		if err != nil {
			return err
		}
		if tag != writeClaimTag+strings.TrimPrefix(name, writeClaimPrefix) {
			continue
		}
		if lock == nil {
			lock, err = c.store.lock(ctx, r)
			if err != nil {
				return err
			}
			defer lock.Close()
			if repaired, _ := ctx.Value(sourceRepairKey{}).(*bool); repaired != nil {
				*repaired = true
			}
		}
		if err := c.retireSourceAddWrite(dir, name, tag); err != nil {
			return err
		}
	}
	return nil
}
