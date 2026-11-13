package storagebase

import (
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"strings"
	"syscall"
)

type PendingRoot struct{ Path, Domain string }

var TransactionRoots = []PendingRoot{{"/var/lib/panasms-agent/storage", "partitionfs"}, {"/var/lib/panasms-agent/local-mounts", "localmounts"}}

type TransactionEnvelope struct {
	Schema   int                          `json:"schema"`
	Domain   string                       `json:"domain"`
	Action   string                       `json:"action"`
	Target   string                       `json:"target"`
	Identity storagequery.StorageIdentity `json:"identity"`
	Phase    string                       `json:"phase"`
}

// Call under DomainLock after fresh identity capture. The owning domain must
// inspect its own pending journal before any retry; this scan never clears one.
func CheckPendingRoots(domain, target string, identity storagequery.StorageIdentity) error {
	if (domain != "partitionfs" && domain != "localmounts" && domain != "raid") || identity.BootID == "" || len(identity.Devices) == 0 {
		return reject("Storage transaction identity is invalid")
	}
	return checkPendingRoots(TransactionRoots, 0, domain, target, identity)
}
func checkPendingRoots(roots []PendingRoot, owner int, domain, target string, identity storagequery.StorageIdentity) error {
	for _, root := range roots {
		if err := SecureDirectory(root.Path, owner, false); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		entries, err := os.ReadDir(root.Path)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if strings.Contains(entry.Name(), ".history-") {
				continue
			}
			temporary := strings.HasPrefix(entry.Name(), ".journal-") || strings.HasPrefix(entry.Name(), ".panasms-")
			if !temporary && !strings.HasSuffix(entry.Name(), ".json") {
				return reject("Unknown storage transaction evidence. Inspect it before continuing.")
			}
			fd, err := unix.Open(filepath.Join(root.Path, entry.Name()), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			f := os.NewFile(uintptr(fd), entry.Name())
			st, err := f.Stat()
			if err != nil {
				f.Close()
				return err
			}
			raw := st.Sys().(*syscall.Stat_t)
			if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || int(raw.Uid) != owner || raw.Nlink != 1 {
				f.Close()
				return reject("Storage transaction permissions are unsafe")
			}
			if temporary {
				f.Close()
				continue
			}
			data, err := io.ReadAll(io.LimitReader(f, (2<<20)+1))
			f.Close()
			if err != nil {
				return err
			}
			if len(data) > 2<<20 {
				return reject("Storage transaction evidence is too large")
			}
			var record TransactionEnvelope
			if err = json.Unmarshal(data, &record); err != nil {
				return reject("Storage transaction evidence is invalid")
			}
			if record.Schema != 1 || record.Domain != root.Domain || record.Action == "" || !strings.HasPrefix(record.Target, "/dev/") || record.Identity.BootID == "" || len(record.Identity.Devices) == 0 || (record.Phase != "pending" && record.Phase != "complete") {
				return reject("Storage transaction evidence is invalid")
			}
			targetFound := false
			for _, d := range record.Identity.Devices {
				if !strings.HasPrefix(d.Path, "/dev/") || d.DeviceNumber == "" || d.DiskSequence == "" {
					return reject("Storage transaction identity is invalid")
				}
				if d.Path == record.Target {
					targetFound = true
				}
			}
			if !targetFound {
				return reject("Storage transaction identity is invalid")
			}
			if record.Phase == "complete" || (record.Domain == domain && record.Target == target) {
				continue
			}
			for _, old := range record.Identity.Devices {
				for _, current := range identity.Devices {
					if old.Path == current.Path || old.DeviceNumber == current.DeviceNumber || (old.WWN != "" && old.WWN == current.WWN) || (old.Serial != "" && old.Serial == current.Serial) {
						return reject(fmt.Sprintf("Unfinished %s operation on %s. Inspect its recovery report before changing this storage.", record.Domain, record.Target))
					}
				}
			}
		}
	}
	return nil
}
