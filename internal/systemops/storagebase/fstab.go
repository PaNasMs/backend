package storagebase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"strings"
	"syscall"
)

func Hash(text string) string    { sum := sha256.Sum256([]byte(text)); return hex.EncodeToString(sum[:]) }
func ReadFstab() (string, error) { return readFstab("/etc/fstab", 0) }
func readFstab(path string, owner int) (string, error) {
	parent, err := folders.OpenDirectory(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil {
		return "", err
	}
	raw := info.Sys().(*syscall.Stat_t)
	if int(raw.Uid) != owner || info.Mode().Perm()&0022 != 0 {
		return "", reject("Storage configuration permissions are unsafe")
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err = f.Stat()
	if err != nil {
		return "", err
	}
	raw = info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || int(raw.Uid) != owner || raw.Nlink != 1 || info.Mode().Perm()&0022 != 0 {
		return "", reject("Storage configuration permissions are unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return "", err
	}
	if len(data) > 1024*1024 {
		return "", reject("Storage configuration is too large")
	}
	return string(data), nil
}

func FstabLock(ctx context.Context) (*os.File, error) {
	return Lock(ctx, "/run/panasms-storage", "fstab.lock", 0)
}

// Callers retain their durable intent until this returns successfully. Retrying
// an already written value still reloads generators after a previous reload failure.
func WriteFstab(ctx context.Context, beforeHash, desired string, r *systemops.Reporter) error {
	lock, err := FstabLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	return writeFstab(ctx, "/etc/fstab", 0, beforeHash, desired, systemops.AtomicWrite, systemops.Command, r)
}
func writeFstab(ctx context.Context, path string, owner int, beforeHash, desired string, write func(string, string, os.FileMode) error, run func(context.Context, []string, systemops.CommandOptions) ([]byte, error), r *systemops.Reporter) error {
	current, err := readFstab(path, owner)
	if err != nil {
		return err
	}
	if Hash(current) != beforeHash && current != desired {
		return reject("Storage configuration changed; review recovery before modifying it")
	}
	if current != desired {
		if err = write(path, desired, 0644); err != nil {
			return err
		}
	}
	_, err = run(ctx, []string{"systemctl", "daemon-reload"}, systemops.CommandOptions{Operation: true, Reporter: r})
	return err
}
func EscapeFstab(path string) string {
	return strings.NewReplacer(`\`, `\134`, " ", `\040`, "\t", `\011`).Replace(path)
}

// Preserve comments and unrelated rows; only a vanished panel-managed UUID may
// be superseded at the selected destination, matching existing installed fstab.
func EditFstab(current string, removeUUIDs map[string]bool, line string, missing func(string) (bool, error)) (string, error) {
	point := ""
	if line != "" {
		fields := strings.Fields(line)
		if len(fields) != 6 {
			return "", reject("Invalid mount configuration")
		}
		point = fields[1]
	}
	kept := []string{}
	removed := false
	for _, row := range strings.Split(strings.TrimSuffix(current, "\n"), "\n") {
		fields := strings.Fields(row)
		if len(fields) == 0 || strings.HasPrefix(strings.TrimSpace(row), "#") {
			kept = append(kept, row)
			continue
		}
		if strings.HasPrefix(fields[0], "UUID=") && removeUUIDs[strings.TrimPrefix(fields[0], "UUID=")] {
			removed = true
			continue
		}
		if point != "" && len(fields) >= 4 && fields[1] == point {
			managed := false
			for _, opt := range strings.Split(fields[3], ",") {
				managed = managed || opt == "x-systemd.device-timeout=30s"
			}
			if !strings.HasPrefix(fields[0], "UUID=") || !managed || missing == nil {
				return "", reject("The mount point is already used by another volume")
			}
			absent, err := missing(strings.TrimPrefix(fields[0], "UUID="))
			if err != nil {
				return "", err
			}
			if !absent {
				return "", reject("The mount point is already used by another volume")
			}
			kept = append(kept, "# PaNasMs: superseded unavailable volume: "+row)
			continue
		}
		kept = append(kept, row)
	}
	if line == "" && !removed {
		return current, nil
	}
	if line != "" {
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n") + "\n", nil
}
