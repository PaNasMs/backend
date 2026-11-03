package networkmounts

import (
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
)

func pinDirectory(path string) (*os.File, error) { return folders.OpenDirectory(path) }
func unmountPinned(point string, expected folders.LiveMount) error {
	return storagebase.UnmountPinned(point, expected)
}
func unmountPinnedWith(point string, expected folders.LiveMount, before func() error) error {
	return storagebase.UnmountPinnedWith(point, expected, before)
}
func attachStaged(stage string, target *os.File, before func(uint64) error) (uint64, error) {
	return storagebase.AttachStaged(stage, target, before)
}
