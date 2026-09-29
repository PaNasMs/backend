package database

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func RequireExistingAfterInitialization(path string) error {
	_, err := os.Stat(path + ".initialized")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("database %s is missing after initialization; restore the database from backup", path)
	}
	return err
}

func MarkInitialized(path string) error {
	marker := path + ".initialized"
	file, err := os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		os.Remove(marker)
		return err
	}
	if err = file.Close(); err != nil {
		os.Remove(marker)
		return err
	}
	dir, err := os.Open(filepath.Dir(marker))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
