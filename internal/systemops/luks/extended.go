package luks

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
)

type extraState struct {
	Config       *managedConfig
	CrypttabHash [32]byte
	Folder       storagebase.TargetWitness
	HeaderHash   string
}

func slotParam(v any) (int, error) {
	var n int
	switch v := v.(type) {
	case int:
		n = v
	case int64:
		n = int(v)
	case json.Number:
		i, e := v.Int64()
		if e != nil {
			return 0, reject("Invalid key slot")
		}
		n = int(i)
	case float64:
		n = int(v)
		if float64(n) != v {
			return 0, reject("Invalid key slot")
		}
	default:
		return 0, reject("Invalid key slot")
	}
	if n < 0 || n > 31 {
		return 0, reject("Invalid key slot")
	}
	return n, nil
}

func manualSlots(slots []int, cfg *managedConfig) []int {
	if cfg == nil {
		return slots
	}
	return slices.DeleteFunc(slices.Clone(slots), func(slot int) bool { return slot == cfg.Slot })
}

func otherUsable(slots []int, remove int) bool {
	for _, n := range slots {
		if n != remove {
			return true
		}
	}
	return false
}

func prepareExtra(ctx context.Context, action string, params map[string]any, p *prepared) (any, []string, error) {
	config, err := readManagedConfig(p.UUID)
	if err != nil {
		return nil, nil, err
	}
	rows, err := readCrypttab()
	if err != nil {
		return nil, nil, err
	}
	return planExtraState(ctx, action, params, p, config, rows)
}

func planExtraState(ctx context.Context, action string, params map[string]any, p *prepared, config *managedConfig, rows []string) (any, []string, error) {
	var err error
	s := extraState{Config: config, CrypttabHash: sha256.Sum256([]byte(strings.Join(rows, "\n")))}
	d := []string{p.Target, "LUKS2: " + p.UUID}
	switch action {
	case "luks.key-add", "luks.key-remove", "luks.auto-enable", "luks.auto-disable":
		if _, err = passphrase(params, "passphrase"); err != nil {
			return nil, nil, err
		}
	}
	switch action {
	case "luks.key-add":
		if _, err = passphrase(params, "password"); err != nil {
			return nil, nil, err
		}
		if len(p.Meta.Slots) >= 32 {
			return nil, nil, reject("No free LUKS key slot")
		}
		d = append(d, "A new password will be added. Existing passwords remain valid.")
	case "luks.key-remove":
		slot, err := slotParam(params["slot"])
		if err != nil {
			return nil, nil, err
		}
		if !slices.Contains(p.Meta.Slots, slot) || !otherUsable(manualSlots(p.Meta.UsableSlots, config), slot) {
			return nil, nil, reject("The last LUKS key cannot be removed")
		}
		if config != nil && slot == config.Slot {
			return nil, nil, reject("Disable automatic unlocking before removing its key")
		}
		d = append(d, fmt.Sprintf("Key slot: %d", slot), "The selected key will be revoked. Old header backups can restore revoked keys.")
	case "luks.auto-enable":
		st, err := os.Stat("/usr/lib/systemd/systemd-cryptsetup")
		if err != nil || !st.Mode().IsRegular() {
			return nil, nil, reject("Install systemd-cryptsetup before enabling automatic unlocking")
		}
		if config != nil && config.Name != p.Name {
			return nil, nil, reject("Use the existing automatic-unlock name")
		}
		if config == nil && len(p.Meta.Slots) >= 32 {
			return nil, nil, reject("No free LUKS key slot")
		}
		if _, err := updatedCrypttab(rows, p.UUID, config, p.Name); err != nil {
			return nil, nil, err
		}
		d = append(d, "A root-only key will be stored on the system disk. This does not protect against theft of the whole NAS.", "Automatic unlocking takes effect at the next startup. Keep a separate working password and header backup.")
	case "luks.auto-disable":
		if config == nil {
			return nil, nil, reject("Automatic unlocking is not configured")
		}
		if !otherUsable(p.Meta.UsableSlots, config.Slot) {
			return nil, nil, reject("Keep another working LUKS key first")
		}
		if _, err := updatedCrypttab(rows, p.UUID, config, ""); err != nil {
			return nil, nil, err
		}
		d = append(d, "Automatic unlocking will be disabled and its stored key revoked. The current mapping stays open.")
	case "luks.header-backup", "luks.header-restore":
		if action == "luks.header-restore" && config != nil {
			return nil, nil, reject("Disable automatic unlocking before restoring a header")
		}
		folder, _ := params["folder"].(string)
		dir, w, err := headerDirectory(folder)
		if err != nil {
			return nil, nil, err
		}
		defer dir.Close()
		s.Folder = w
		base := p.UUID + ".luks-header"
		d = append(d, filepath.Join(folder, base))
		if action == "luks.header-backup" {
			var st unix.Stat_t
			err = unix.Fstatat(int(dir.Fd()), base, &st, unix.AT_SYMLINK_NOFOLLOW)
			if err == nil {
				return nil, nil, reject("A header backup already exists in this folder")
			}
			if !errors.Is(err, unix.ENOENT) {
				return nil, nil, err
			}
			d = append(d, "Store this backup separately. It can restore revoked keys and does not contain your files.")
		} else {
			cache, digest, err := snapshotHeader(ctx, dir, base, p.UUID)
			if err != nil {
				return nil, nil, err
			}
			cache.Close()
			s.HeaderHash = digest
			d = append(d, "Restoring the header replaces current keys with keys from the backup. Files are not restored.")
		}
	default:
		return nil, nil, reject("Unknown LUKS action")
	}
	return s, d, nil
}

func managedCrypttabRow(name, uuid string) string {
	key := filepath.Join(managedConfigDir, uuid+".key")
	return name + " UUID=" + uuid + " " + key + " luks,nofail,headless,x-systemd.device-timeout=30s"
}

func inspectCrypttab(rows []string, uuid string, cfg *managedConfig, mapping string) (kept []string, found bool, err error) {
	marker := "# PaNasMs " + uuid
	result := make([]string, 0, len(rows)+2)

	for i := 0; i < len(rows); i++ {
		row := rows[i]
		if row == marker {
			if found || cfg == nil || i+1 >= len(rows) || rows[i+1] != managedCrypttabRow(cfg.Name, uuid) {
				return nil, false, reject("The managed crypttab entry changed; review the system configuration")
			}
			found = true
			i++
			continue
		}
		fields := strings.Fields(row)
		if mapping != "" && len(fields) > 0 && !strings.HasPrefix(fields[0], "#") && (fields[0] == mapping || len(fields) > 1 && strings.EqualFold(fields[1], "UUID="+uuid)) {
			return nil, false, reject("This LUKS volume or mapping already has an unmanaged crypttab entry")
		}
		result = append(result, row)
	}
	return result, found, nil
}

func updatedCrypttab(rows []string, uuid string, cfg *managedConfig, mapping string) (string, error) {
	result, _, err := inspectCrypttab(rows, uuid, cfg, mapping)
	if err != nil {
		return "", err
	}
	if mapping != "" {
		result = append(result, "# PaNasMs "+uuid, managedCrypttabRow(mapping, uuid))
	}
	return strings.Join(result, "\n") + "\n", nil
}

func cryptAction(ctx context.Context, args []string, input string, mutate bool, r *systemops.Reporter) error {
	var data []byte
	if input != "" {
		data = []byte(input)
		defer clear(data)
	}
	_, err := systemops.Command(ctx, append([]string{"cryptsetup"}, args...), systemops.CommandOptions{Input: data, Operation: mutate, Timeout: 300 * time.Second, Reporter: r})
	return err
}

func unlocks(ctx context.Context, path, secret string, slot int) error {
	args := []string{"open", "--test-passphrase", "--key-file", "-"}
	if slot >= 0 {
		args = append(args, "--key-slot", strconv.Itoa(slot))
	}
	return cryptAction(ctx, append(args, path), secret, false, nil)
}

func authorizeOther(ctx context.Context, path, secret string, slots []int, excluded int) error {
	for _, slot := range slots {
		if slot == excluded {
			continue
		}
		err := unlocks(ctx, path, secret, slot)
		if err == nil {
			return nil
		}
		if code, ok := systemops.CommandExitCode(err); !ok || code != 2 {
			return err
		}
	}
	return reject("Enter a password that unlocks a different key slot")
}

func fdPath(f *os.File) string { return fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), f.Fd()) }

func anonymousFile(label string) (*os.File, error) {
	fd, err := unix.MemfdCreate(label, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), label)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func sealFile(f *os.File) error {
	_, err := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_WRITE|unix.F_SEAL_SEAL)
	return err
}

func executeExtra(ctx context.Context, action string, params map[string]any, p *prepared, path string, r *systemops.Reporter) (map[string]any, error) {
	s := p.Extra.(extraState)
	secret, _ := params["passphrase"].(string)
	var err error
	switch action {
	case "luks.key-add":
		if err = unlocks(ctx, path, secret, -1); err != nil {
			return nil, err
		}
		newKey, _ := params["password"].(string)
		// Reconcile a previously completed key addition after worker interruption.
		if err = unlocks(ctx, path, newKey, -1); err != nil {
			if code, ok := systemops.CommandExitCode(err); !ok || code != 2 {
				return nil, err
			}
			f, e := anonymousFile("luks-input")
			if e != nil {
				return nil, e
			}
			defer f.Close()
			if _, e = f.WriteString(newKey); e != nil {
				return nil, e
			}
			if e = sealFile(f); e != nil {
				return nil, e
			}
			if err = cryptAction(ctx, []string{"luksAddKey", "--key-file", "-", path, fdPath(f)}, secret, true, r); err == nil {
				err = unlocks(ctx, path, newKey, -1)
			}
		}
	case "luks.key-remove":
		slot, e := slotParam(params["slot"])
		if e != nil {
			return nil, e
		}
		if err = authorizeOther(ctx, path, secret, manualSlots(p.Meta.UsableSlots, s.Config), slot); err == nil {
			err = killSlot(ctx, path, secret, slot, r)
		}
	case "luks.auto-enable":
		if err = unlocks(ctx, path, secret, -1); err == nil {
			err = enableAuto(ctx, p, path, s.Config, secret, r)
		}
	case "luks.auto-disable":
		if err = authorizeOther(ctx, path, secret, p.Meta.UsableSlots, s.Config.Slot); err == nil {
			err = disableAuto(ctx, p, path, s.Config, secret, r)
		}
	case "luks.header-backup", "luks.header-restore":
		err = executeHeader(ctx, action, p, path, s, r)
	default:
		err = reject("Unknown LUKS action")
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"target": p.Target, "message": "Operation complete."}, nil
}

func killSlot(ctx context.Context, path, secret string, slot int, r *systemops.Reporter) error {
	return cryptAction(ctx, []string{"luksKillSlot", "--batch-mode", "--key-file", "-", path, strconv.Itoa(slot)}, secret, true, r)
}

func changeBootConfig(ctx context.Context, cfg *managedConfig, mapping string, r *systemops.Reporter) error {
	rows, err := readCrypttab()
	if err != nil {
		return err
	}
	value, err := updatedCrypttab(rows, cfg.UUID, cfg, mapping)
	if err != nil {
		return err
	}
	if err = systemops.AtomicWrite(crypttabPath, value, 0600); err != nil {
		return err
	}
	_, err = systemops.Command(ctx, []string{"systemctl", "daemon-reload"}, systemops.CommandOptions{Operation: true, Reporter: r})
	return err
}

func managedKey(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		st := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || st.Uid != 0 || st.Nlink != 1 || info.Size() != 128 {
			err = reject("The automatic-unlock key is missing or unsafe")
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func enableAuto(ctx context.Context, p *prepared, path string, cfg *managedConfig, secret string, r *systemops.Reporter) error {
	if err := storagebase.SecureDirectory(managedConfigDir, 0, true); err != nil {
		return err
	}
	key := filepath.Join(managedConfigDir, p.UUID+".key")
	if cfg == nil {
		if _, err := os.Lstat(key); err == nil || !errors.Is(err, os.ErrNotExist) {
			return reject("An unowned automatic-unlock key already exists")
		}
		slot := 31
		for slot >= 0 && slices.Contains(p.Meta.Slots, slot) {
			slot--
		}
		if slot < 0 {
			return reject("No free LUKS key slot")
		}
		cfg = &managedConfig{UUID: p.UUID, Name: p.Name, Slot: slot}
		record, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		if err = systemops.AtomicWrite(filepath.Join(managedConfigDir, p.UUID+".json"), string(record), 0600); err != nil {
			return err
		}
	}
	f, err := managedKey(key)
	occupied := slices.Contains(p.Meta.Slots, cfg.Slot)
	if errors.Is(err, os.ErrNotExist) && !occupied {
		var random [64]byte
		if _, err = rand.Read(random[:]); err != nil {
			return err
		}
		defer clear(random[:])
		// Link only a complete, synced anonymous inode into the private key directory.
		dir, err := os.Open(managedConfigDir)
		if err != nil {
			return err
		}
		defer dir.Close()
		payload := make([]byte, 128)
		hex.Encode(payload, random[:])
		defer clear(payload)
		if err = publishFile(dir, filepath.Base(key), bytes.NewReader(payload), -1, -1); err != nil {
			return err
		}
		f, err = managedKey(key)
		if err != nil {
			return err
		}
	} else if err != nil {
		if occupied {
			return reject("The reserved slot is occupied. Restore its original root-only managed key file before retrying.")
		}
		return err
	}
	defer f.Close()
	if !occupied {
		if err = cryptAction(ctx, []string{"luksAddKey", "--key-slot", strconv.Itoa(cfg.Slot), "--key-file", "-", path, fdPath(f)}, secret, true, r); err != nil {
			return err
		}
	}
	if err = verifyManaged(ctx, path, f, cfg.Slot); err != nil {
		return err
	}
	return changeBootConfig(ctx, cfg, cfg.Name, r)
}

func verifyManaged(ctx context.Context, path string, f *os.File, slot int) error {
	err := cryptAction(ctx, []string{"open", "--test-passphrase", "--key-slot", strconv.Itoa(slot), "--key-file", fdPath(f), path}, "", false, nil)
	if code, ok := systemops.CommandExitCode(err); ok && code == 2 {
		return reject("The stored key does not unlock the reserved slot. Restore its original managed key file before retrying.")
	}
	return err
}

func disableAuto(ctx context.Context, p *prepared, path string, cfg *managedConfig, secret string, r *systemops.Reporter) error {
	key := filepath.Join(managedConfigDir, p.UUID+".key")
	occupied := slices.Contains(p.Meta.Slots, cfg.Slot)
	if occupied {
		f, err := managedKey(key)
		if err != nil {
			return reject("The reserved slot is occupied. Restore its original root-only managed key file before retrying.")
		}
		defer f.Close()
		if err = verifyManaged(ctx, path, f, cfg.Slot); err != nil {
			return err
		}
	}
	if err := changeBootConfig(ctx, cfg, "", r); err != nil {
		return err
	}
	if occupied {
		if err := killSlot(ctx, path, secret, cfg.Slot, r); err != nil {
			return err
		}
	}
	d, err := os.Open(managedConfigDir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = os.Remove(key); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = d.Sync(); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(managedConfigDir, p.UUID+".json")); err != nil {
		return err
	}
	return d.Sync()
}
