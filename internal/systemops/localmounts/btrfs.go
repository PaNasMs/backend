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
