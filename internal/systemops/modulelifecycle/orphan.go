package modulelifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"

	"golang.org/x/sys/unix"
)

var journalTemporary = regexp.MustCompile(`^(\.write-[a-f0-9]{32}|\.panasms-[a-z0-9_]{8})$`)

func orphanTransaction(directory *os.File, owner uint32) (*transaction, error) {
	entries, err := directory.ReadDir(33)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 32 {
		return nil, reject("Unrecognized files remain in the module transaction; preserve them for inspection")
	}
	type entry struct {
		Name           string
		Device, Inode  uint64
		Mode, UID, GID uint32
		Hash           string
	}
	items := []entry{}
	for _, item := range entries {
		if !journalTemporary.MatchString(item.Name()) {
			return nil, reject("Unrecognized files remain in the module transaction; preserve them for inspection")
		}
		raw, stat, err := readOwnedSnapshotAt(directory, item.Name(), owner, 16<<20)
		if err != nil {
			return nil, err
		}
		if stat.Mode&0777 != 0600 {
			return nil, reject("Module transaction temporary file permissions are unsafe")
		}
		digest := sha256.Sum256(raw)
		items = append(items, entry{item.Name(), uint64(stat.Dev), stat.Ino, stat.Mode & 0777, stat.Uid, stat.Gid, hex.EncodeToString(digest[:])})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	var dir unix.Stat_t
	if err = unix.Fstat(int(directory.Fd()), &dir); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(struct {
		Device, Inode uint64
		Files         []entry
	}{uint64(dir.Dev), dir.Ino, items})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	return &transaction{orphan: true, orphanFingerprint: hex.EncodeToString(digest[:])}, nil
}
