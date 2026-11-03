package localmounts

import (
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func trustedRemountParent(point string) (storagebase.TargetWitness, error) {
	for path := filepath.Dir(point); ; path = filepath.Dir(path) {
		f, err := folders.OpenDirectory(path)
		if err != nil {
			return storagebase.TargetWitness{}, err
		}
		st, err := f.Stat()
		f.Close()
		if err != nil {
			return storagebase.TargetWitness{}, err
		}
		if st.Sys().(*syscall.Stat_t).Uid != 0 || st.Mode().Perm()&0022 != 0 {
			return storagebase.TargetWitness{}, reject("Repair or changing an active mount requires a root-owned mount-point parent that other users cannot modify. Unmount it and choose a protected mount point first.")
		}
		if path == "/" {
			break
		}
	}
	witness, f, err := storagebase.ObserveTarget(filepath.Dir(point))
	if f != nil {
		f.Close()
	}
	return witness, err
}
func refreshRemountTarget(v *plan) error {
	if v.remountParent == nil {
		return nil
	}
	now, err := trustedRemountParent(v.point)
	if err != nil {
		return err
	}
	if now != *v.remountParent {
		return reject("The mount-point parent changed. Review recovery before continuing.")
	}
	witness, f, err := storagebase.ObserveTarget(v.point)
	if f != nil {
		defer f.Close()
	}
	if err != nil {
		return err
	}
	if witness.Ancestor != v.point {
		return reject("The mount-point directory disappeared")
	}
	if f == nil {
		return os.ErrNotExist
	}
	if err = emptyDirectory(f); err != nil {
		return err
	}
	v.witness = witness
	return nil
}

func staleBlockMount(m folders.LiveMount) bool {
	if !strings.HasPrefix(m.Source, "/dev/") || filepath.Clean(m.Source) != m.Source || strings.ContainsAny(m.Source, "[]\n\r") || m.Device == "" {
		return false
	}
	// A pseudo filesystem can choose an arbitrary /dev-like source label.
	if m.Root != "/" {
		return false
	}
	switch m.FSType {
	case "ext2", "ext3", "ext4", "xfs", "vfat", "exfat", "ntfs", "ntfs3", "f2fs", "jfs":
	default:
		return false
	}
	majorText, minorText, ok := strings.Cut(m.Device, ":")
	major, majorErr := strconv.ParseUint(majorText, 10, 32)
	_, minorErr := strconv.ParseUint(minorText, 10, 32)
	if !ok || majorErr != nil || minorErr != nil || major == 0 {
		return false
	}
	_, sourceErr := os.Stat(m.Source)
	_, deviceErr := os.Stat(filepath.Join("/sys/dev/block", m.Device))
	return os.IsNotExist(sourceErr) && os.IsNotExist(deviceErr)
}
