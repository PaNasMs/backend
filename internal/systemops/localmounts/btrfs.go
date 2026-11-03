package localmounts

import (
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
)

func verifyBtrfsPoint(point, target, uuid string) error {
	f, err := folders.OpenDirectory(point)
	if err != nil {
		return err
	}
	defer f.Close()
	return storagebase.VerifyBtrfsMount(f, target, uuid)
}
func mountedPoint(row map[string]any, point string) bool {
	values, _ := row["mountpoints"].([]any)
	for _, value := range values {
		if value == point {
			return true
		}
	}
	return false
}

func recordedBtrfsUUID(live folders.LiveMount) (string, error) {
	dir, err := folders.OpenDirectory(live.Target)
	if err != nil {
		return "", err
	}
	defer dir.Close()
	if _, err = folders.DirectoryMount(dir, []folders.LiveMount{live}); err != nil {
		return "", err
	}
	return storagebase.BtrfsUUID(dir)
}
