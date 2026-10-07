package networknative

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validateFiles(files map[string]*string) error {
	netplan := false
	for path := range files {
		if strings.HasPrefix(path, "/etc/netplan/") {
			netplan = true
		}
	}
	if !netplan {
		return nil
	}
	temporary, err := os.MkdirTemp("", "panasms-native-netplan-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	for _, directory := range []string{"/lib/netplan", "/etc/netplan", "/run/netplan"} {
		paths, err := filepath.Glob(directory + "/*.yaml")
		if err != nil {
			return err
		}
		for _, path := range paths {
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() > 1024*1024 {
				return fmt.Errorf("Unsupported Netplan configuration file")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err = stageFile(filepath.Join(temporary, path), text(string(data))); err != nil {
				return err
			}
		}
	}
	for path, content := range files {
		if !strings.HasPrefix(path, "/etc/netplan/") {
			continue
		}
		if err = stageFile(filepath.Join(temporary, path), content); err != nil {
			return err
		}
	}
	return run("netplan", "generate", "--root-dir", temporary)
}

func stageFile(path string, value *string) error {
	if value == nil {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(*value), 0600)
}
