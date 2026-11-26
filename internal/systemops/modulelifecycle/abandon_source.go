package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

// AbandonSourceAdd is a local operator command, never a recovery action.
func AbandonSourceAdd(ctx context.Context, digest string) error {
	if os.Geteuid() != 0 {
		return reject("Root permissions required")
	}
	s, err := installedLifecycle()
	if err != nil {
		return err
	}
	return s.abandonSourceAdd(ctx, digest)
}

func (s lifecycle) abandonSourceAdd(ctx context.Context, digest string) error {
	if _, err := hex.DecodeString(digest); err != nil || len(digest) != sha256.Size*2 || strings.ToLower(digest) != digest {
		return reject("Expected lowercase SHA256 of reviewed pending journal")
	}
	lease, err := acquireMaintenance(s.maintenance, s.owner)
	if err != nil {
		return err
	}
	defer lease.file.Close()
	lock, err := s.lock(ctx, nil)
	if err != nil {
		return err
	}
	defer lock.Close()
	dir, err := s.configDir()
	if err != nil {
		return err
	}
	defer dir.Close()
	archive := "module-sources.abandoned-" + digest + ".json"
	raw, err := readOwnedAt(dir, sourceIntent, s.owner, 2<<20)
	if errors.Is(err, os.ErrNotExist) {
		// A crash after rename but before directory sync needs only another sync.
		receipt, e := readOwnedAt(dir, archive, s.owner, 2<<20)
		if e != nil {
			return e
		}
		if fmt.Sprintf("%x", sha256.Sum256(receipt)) != digest {
			return reject("Abandoned journal digest mismatch")
		}
		return syncDir(dir)
	}
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != digest {
		return reject("Pending journal differs from the reviewed journal")
	}
	var c sourceChange
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return err
	}
	if dec.Decode(new(any)) != io.EOF {
		return reject("Unexpected trailing journal data")
	}
	if c.Add == nil || len(c.Sources) == 0 || len(c.Sources) > 16 || !reflect.DeepEqual(c.Sources[len(c.Sources)-1], c.Add) || c.Remove || c.RemovePublishers != nil || c.RemovePEMHashes != nil || c.Withdraw != "" || c.WithdrawRow != nil {
		return reject("Expected a pending addition only")
	}
	ids, err := sourceSigners(c.Add)
	if err != nil || len(ids) != 1 || ids[0] != c.Publisher || strings.HasPrefix(c.Publisher, "panasms-") {
		return reject("Invalid pending publisher")
	}
	_, fp, err := sourcePublic(c.Key)
	if err != nil || text(c.Add, "fingerprint") != fp {
		return reject("Invalid pending publisher fingerprint")
	}
	id, url := text(c.Add, "id"), text(c.Add, "url")
	if identifier(id) != nil {
		return reject("Invalid pending source ID")
	}
	if _, err := catalogURL(url, false); err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		if strings.HasPrefix(name, sourceStagePrefix) {
			return reject("Resolve the repository publication stage first")
		}
	}
	rows, err := s.sourcesAt(dir)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if text(row, "id") == id || text(row, "url") == url {
			return reject("A matching repository is visible; journal retained")
		}
	}
	keys, err := trustedDirectory(s.keys, s.owner)
	if err != nil {
		return err
	}
	defer keys.Close()
	_, err = readOwnedAt(keys, c.Publisher+".pem", s.owner, 8192)
	if err == nil {
		return reject("Publisher key is present; journal retained")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fd := int(dir.Fd())
	if err := unix.Renameat2(fd, sourceIntent, fd, archive, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return syncDir(dir)
}
