package raid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/disksleep"
	"panasms.local/backend/internal/systemops/localmounts"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

func Execute(ctx context.Context, action string, params map[string]any, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	domain, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer domain.Close()
	s := defaultService()
	var result json.RawMessage
	applying := false
	err = disksleep.WithStorageLock(func() error {
		p, err := s.prepare(ctx, action, params)
		if err != nil {
			return err
		}
		if expected == "" || p.fingerprint != expected {
			return reject("State has changed. Review a new operation plan.")
		}
		for _, path := range sortedKeys(p.Identities) {
			lock, err := storagebase.DeviceLock(ctx, path)
			if err != nil {
				return err
			}
			defer lock.Close()
		}
		p, err = s.prepare(ctx, action, params)
		if err != nil {
			return err
		}
		if p.fingerprint != expected {
			return reject("State has changed. Review a new operation plan.")
		}
		m := mutation{s: s, p: p, ctx: ctx, opts: systemops.CommandOptions{Operation: true, Reporter: r}}
		applying = true
		msg, err := m.apply(action)
		if err != nil {
			return err
		}
		output := map[string]string{}
		if msg != "" {
			output["message"] = msg
		}
		if action == "raid.convert" || action == "raid.grow" {
			output["target"] = p.Target
		}
		result, err = json.Marshal(output)
		return err
	})
	if err != nil && !applying {
		return nil, systemops.BeforeMutation(err)
	}
	return result, err
}

type mutation struct {
	s    *service
	p    *prepared
	ctx  context.Context
	opts systemops.CommandOptions
}

func (m mutation) identity(path string) (storagequery.DeviceIdentity, error) {
	for _, d := range m.p.Identities[path].Devices {
		if d.Path == path {
			return d, nil
		}
	}
	return storagequery.DeviceIdentity{}, reject("Could not verify storage identity")
}

func (m mutation) verify(path string) error {
	id, err := m.identity(path)
	if err != nil {
		return err
	}
	dev, err := storagebase.PinDevice(id)
	if err != nil {
		return err
	}
	return dev.Close()
}

func (m mutation) run(paths []string, args ...string) ([]byte, error) {
	for _, path := range paths {
		if err := m.verify(path); err != nil {
			return nil, err
		}
	}
	return m.s.run(m.ctx, args, m.opts)
}

func (m mutation) verifyBlank(path string) error {
	id, err := m.identity(path)
	if err != nil {
		return err
	}
	pin, err := storagebase.PinDevice(id)
	if err != nil {
		return err
	}
	defer pin.Close()
	// blkid -p returns 2 for no signature and 8 for an ambiguous probe.
	raw, err := m.s.run(m.ctx, []string{"blkid", "-p", "-o", "export", pin.Path()}, systemops.CommandOptions{Accepted: []int{0, 2}})
	if err != nil {
		return err
	}
	for _, line := range strings.Fields(string(raw)) {
		if strings.HasPrefix(line, "TYPE=") || strings.HasPrefix(line, "PTTYPE=") || strings.HasPrefix(line, "USAGE=") {
			return reject("The selected member contains data or RAID metadata")
		}
	}
	return nil
}

func (m mutation) apply(action string) (string, error) {
	s, p := m.s, m.p
	if p.Extra != "" {
		if err := m.verifyBlank(p.Extra); err != nil {
			return "", err
		}
	}
	switch action {
	case "raid.create":
		return "", m.create()
	case "raid.delete":
		return "", m.remove()
	case "raid.pause", "raid.check", "raid.check-stop":
		value := map[string]string{"raid.pause": "frozen", "raid.check": "check", "raid.check-stop": "idle"}[action]
		if err := m.verify(p.Target); err != nil {
			return "", err
		}
		fresh, err := s.readArray(filepath.Base(p.Target))
		if err != nil {
			return "", err
		}
		if fresh.UUID != p.State.UUID || fresh.Sync != p.State.Sync || fresh.Reshaping != p.State.Reshaping {
			return "", reject("Array maintenance changed. Review a new operation plan.")
		}
		path := filepath.Join(s.sys, filepath.Base(p.Target), "md", "sync_action")
		if err = os.WriteFile(path, []byte(value), 0); err != nil {
			return "", err
		}
		if action == "raid.pause" {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", err
			}
			if strings.TrimSpace(string(b)) != "frozen" {
				return "", reject("Could not confirm reshape pause")
			}
			return "Reshape paused. Position saved.", nil
		}
	case "raid.resume":
		if err := m.verify(p.Target); err != nil {
			return "", err
		}
		return "Reshape resumed. Progress is shown on the array card.", s.resume(m.ctx, p.Target, p.State, p.Record, m.opts.Reporter)
	case "raid.convert":
		return m.convert()
	case "raid.grow":
		backup, err := m.recordReshape(true)
		if err != nil {
			return "", err
		}
		_, err = m.run([]string{p.Target, p.Extra}, scoped("grow", "--grow", p.Target, "--raid-devices="+strconv.Itoa(p.NewCount), "--add", p.Extra)...)
		if err != nil {
			return "", fmt.Errorf("Could not confirm expansion startup. Check array membership and progress before retrying: %w", m.failedStart(backup, err))
		}
		count, err := os.ReadFile(filepath.Join(s.sys, filepath.Base(p.Target), "md", "raid_disks"))
		if err != nil {
			return "", err
		}
		fields := strings.Fields(string(count))
		if len(fields) == 0 || fields[0] != strconv.Itoa(p.NewCount) {
			return "", reject("The new member count is not confirmed. Refresh array state before retrying.")
		}
		return "Array expansion started. Wait for reshape to finish on the RAID card. Partition and file system sizes are unchanged.", nil
	case "raid.add", "raid.replace":
		if action == "raid.replace" && slices.ContainsFunc(p.State.Members, func(member member) bool { return member.Path == p.Old && slices.Contains(member.State, "faulty") }) {
			if _, err := m.run([]string{p.Target, p.Old}, "mdadm", "--manage", p.Target, "--remove", p.Old); err != nil {
				return "", err
			}
		} else if action == "raid.replace" {
			if _, err := m.run([]string{p.Target, p.Extra}, "mdadm", "--manage", p.Target, "--add", p.Extra); err != nil {
				return "", err
			}
			_, err := m.run([]string{p.Target, p.Old, p.Extra}, "mdadm", "--manage", p.Target, "--replace", p.Old, "--with", p.Extra)
			return "", err
		}
		_, err := m.run([]string{p.Target, p.Extra}, "mdadm", "--manage", p.Target, "--add", p.Extra)
		return "", err
	default:
		return "", reject("Unknown RAID operation")
	}
	return "", nil
}

func (m mutation) config(desired string) error {
	raw, err := os.ReadFile(m.s.config)
	if err != nil {
		return err
	}
	if string(raw) != desired && string(raw) != m.p.Config {
		return reject("MD configuration changed. Inspect array state before retrying.")
	}
	if string(raw) != desired {
		if err = systemops.AtomicWrite(m.s.config, desired, 0644); err != nil {
			return err
		}
	}
	_, err = m.run(nil, "update-initramfs", "-u")
	return err
}

func (m mutation) create() error {
	p := m.p
	target := "/dev/md/" + p.Target
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		return reject("Array name is already in use")
	}
	for _, member := range p.Paths {
		if err := m.verifyBlank(member); err != nil {
			return err
		}
	}
	uuid, err := newUUID()
	if err != nil {
		return err
	}
	j, err := m.begin("raid.create", uuid, uuid)
	if err != nil {
		return err
	}
	args := []string{"mdadm", "--create", target, "--uuid=" + uuid, "--run", "--metadata=1.2", "--name=" + p.Target, "--level=" + p.Level, "--raid-devices=" + strconv.Itoa(len(p.Paths))}
	if _, err := m.run(p.Paths, append(args, p.Paths...)...); err != nil {
		return err
	}
	if _, err := m.run(nil, "udevadm", "settle"); err != nil {
		return err
	}
	path, err := m.createdArray(j)
	if err != nil {
		return err
	}
	pf, err := m.s.load(m.ctx)
	if err != nil {
		return err
	}
	if err = pf.Protected(path, false); err != nil {
		return err
	}
	id, err := m.s.identity(pf, path)
	if err != nil {
		return err
	}
	p.Identities[path] = id
	d, err := m.identity(path)
	if err != nil {
		return err
	}
	pin, err := storagebase.PinDevice(d)
	if err != nil {
		return err
	}
	defer pin.Close()
	// The array may expose signatures left by data on its previous members.
	if _, err = m.run([]string{path}, "wipefs", "--all", "--", pin.Path()); err != nil {
		return err
	}
	if err = j.save("register"); err != nil {
		return err
	}
	return m.register(j)
}
func (m mutation) createdArray(j *intent) (string, error) {
	p := m.p
	path, err := m.s.resolve("/dev/md/" + p.Target)
	if err != nil {
		return "", err
	}

	a, err := m.s.readArray(filepath.Base(path))
	if err != nil {
		return "", err
	}
	if compactUUID(a.UUID) != compactUUID(j.UUID) || a.Level != "raid"+p.Level || len(a.Members) != len(p.Paths) || a.Count != len(p.Paths) {
		return "", reject("Created array membership does not match the reviewed disks")
	}
	for _, dev := range a.Members {
		if !slices.Contains(p.Paths, dev.Path) {
			return "", reject("Created array membership changed")
		}
		if err = m.verify(dev.Path); err != nil {
			return "", err
		}
	}
	return path, nil
}
func (m mutation) register(j *intent) error {
	path, err := m.createdArray(j)
	if err != nil {
		return err
	}

	scan, err := m.run([]string{path}, "mdadm", "--detail", "--scan", path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(scan)), "\n")
	if len(lines) != 1 || withoutArray(lines[0]+"\n", j.UUID) != "" {
		return reject("Could not confirm created array configuration")
	}
	if err = m.config(strings.TrimRight(m.p.Config, "\n") + "\n" + lines[0] + "\n"); err != nil {
		return err
	}
	return j.finish()
}

func (m mutation) recordReshape(growth bool) (string, error) {
	p, s := m.p, m.s
	uuid := p.State.UUID
	if err := storagebase.SecureDirectory(s.reshapeRoot, s.owner, true); err != nil {
		return "", err
	}
	backup := s.backup(uuid)
	if p.Record != nil {
		backup = p.Record.Backup
		uuid = p.Record.UUID
	}
	present, err := backupPresent(backup, s.owner)
	if err != nil {
		return "", err
	}
	if present {
		if p.Record == nil {
			return "", reject("Unrecognized RAID recovery backup")
		}
		if err = os.Rename(backup, fmt.Sprintf("%s.%d.completed", backup, time.Now().UnixNano())); err != nil {
			return "", err
		}
	}
	level := p.Level
	if growth {
		level = strings.TrimPrefix(p.State.Level, "raid")
	}
	raw, err := json.Marshal(reshapeRecord{UUID: uuid, Target: p.Target, Level: level, Members: p.NewCount, SourceCount: p.State.Count, Backup: backup, Growth: growth})
	if err != nil {
		return "", err
	}
	if err = systemops.AtomicWrite(recordPath(backup), string(raw), 0600); err != nil {
		return "", err
	}
	return backup, nil
}
func (m mutation) convert() (string, error) {
	p := m.p
	backup, err := m.recordReshape(false)
	if err != nil {
		return "", err
	}
	if p.Extra != "" {
		if _, err = m.run([]string{p.Target, p.Extra}, "mdadm", "--manage", p.Target, "--add", p.Extra); err != nil {
			return "", m.failedStart(backup, err)
		}
	}
	_, err = m.run([]string{p.Target}, scoped("convert", "--grow", p.Target, "--level="+p.Level, "--raid-devices="+strconv.Itoa(p.NewCount), "--backup-file="+backup)...)
	if err != nil {
		return "", m.failedStart(backup, err)
	}
	return "RAID conversion started. Check progress on the array card before changing storage again.", err
}

// Retire an unstarted intent only while the same source membership and idle
// geometry are observable. A partial add or a live backup requires inspection.
func (m mutation) failedStart(backup string, cause error) error {
	a, err := m.s.readArray(filepath.Base(m.p.Target))
	if err != nil {
		return errors.Join(cause, err)
	}
	before := m.p.State
	present, err := backupPresent(backup, m.s.owner)
	if err != nil {
		return errors.Join(cause, err)
	}
	if present || a.Reshaping || a.Sync != "idle" || a.UUID != before.UUID || a.Level != before.Level || a.Count != before.Count || !reflect.DeepEqual(a.Members, before.Members) {
		return cause
	}
	if m.p.Record != nil {
		raw, err := json.Marshal(m.p.Record)
		if err == nil {
			err = systemops.AtomicWrite(recordPath(backup), string(raw), 0600)
		}
		return errors.Join(cause, err)
	}
	return errors.Join(cause, m.s.retireRecord(a.UUID))
}

func (m mutation) remove() error {
	p, s := m.p, m.s
	d := p.Delete
	// Old MD metadata can express its UUID differently in sysfs and mdadm.
	// Read mdadm's identifier from the pinned live array and each member before stopping.
	metadata, err := m.mdUUID(p.Target, "--detail")
	if err != nil {
		return err
	}
	for _, member := range p.State.Members {
		uuid, err := m.mdUUID(member.Path, "--examine")
		if err != nil {
			return err
		}
		if compactUUID(uuid) != compactUUID(metadata) {
			return reject("RAID member metadata does not match the reviewed array")
		}
	}
	j, err := m.begin("raid.delete", p.State.UUID, metadata)
	if err != nil {
		return err
	}
	if len(d.Mounts) > 0 {
		unlock, err := accounts.LockRAIDShares(m.ctx, d.Shares, d.Remove)
		if err != nil {
			return err
		}
		defer unlock()
		keep := slices.DeleteFunc(slices.Clone(d.Shares), func(share accounts.StorageShare) bool { return slices.Contains(d.Remove, share) })
		for i, mount := range d.Mounts {
			all, err := s.mounts()
			if err != nil {
				return err
			}
			if err = localmounts.CheckStorageBlockers(m.ctx, d.Mounts[i:], all, keep, nil, nil); err != nil {
				return err
			}
			if err = storagebase.UnmountPinned(mount.Target, mount); err != nil {
				return err
			}
		}
	}
	fresh, err := s.readArray(filepath.Base(p.Target))
	if err != nil {
		return err
	}
	if fresh.UUID != p.State.UUID || fresh.Reshaping || fresh.Sync != "idle" || len(fresh.Members) != len(p.State.Members) {
		return reject("RAID membership or maintenance changed before deletion")
	}
	for i, member := range fresh.Members {
		if member.Path != p.State.Members[i].Path {
			return reject("RAID membership changed before deletion")
		}
		if err = m.verify(member.Path); err != nil {
			return err
		}
	}
	// A crash after stop must not let boot recovery reassemble an array
	// whose member signatures are about to be cleared.
	if err = j.save("before-stop"); err != nil {
		return err
	}
	if _, err = m.run([]string{p.Target}, "mdadm", "--stop", p.Target); err != nil {
		return err
	}
	if err = j.save("stopped"); err != nil {
		return err
	}
	return m.finishDelete(j)
}
func (m mutation) finishDelete(j *intent) error {
	p := m.p
	desired, err := storagebase.RemoveManagedFstabRows(p.Fstab, p.Delete.UUIDs)
	if err != nil {
		return err
	}

	if _, err = m.run(nil, "udevadm", "settle"); err != nil {
		return err
	}
	if err = m.s.retireRecord(j.UUID); err != nil {
		return err
	}
	for _, member := range p.State.Members {
		if err = m.eraseMember(member.Path, j.MetadataUUID); err != nil {
			return err
		}
	}
	current, err := m.s.readFstab()
	if err != nil {
		return err
	}
	if current != desired {
		if err = storagebase.WriteFstab(m.ctx, storagebase.Hash(p.Fstab), desired, m.opts.Reporter); err != nil {
			return err
		}
	}
	if err = m.config(withoutArray(withoutArray(p.Config, j.UUID), j.MetadataUUID)); err != nil {
		return err
	}
	return j.finish()
}

func (m mutation) mdUUID(path, operation string) (string, error) {
	id, err := m.identity(path)
	if err != nil {
		return "", err
	}
	pin, err := storagebase.PinDevice(id)
	if err != nil {
		return "", err
	}
	defer pin.Close()
	raw, err := m.run([]string{path}, "mdadm", operation, "--export", pin.Path())
	if err != nil {
		return "", err
	}
	for _, field := range strings.Fields(string(raw)) {
		if value, ok := strings.CutPrefix(field, "MD_UUID="); ok && uuidPattern.MatchString(value) {
			return value, nil
		}
	}
	return "", reject("Could not verify RAID metadata UUID")
}

func (m mutation) eraseMember(path, uuid string) error {
	id, err := m.identity(path)
	if err != nil {
		return err
	}
	pin, err := storagebase.PinDevice(id)
	if err != nil {
		return err
	}
	defer pin.Close()
	pf, err := m.s.load(m.ctx)
	if err != nil {
		return err
	}
	if err = pf.Protected(path, false); err != nil {
		return err
	}
	if err = pf.Unused(path, false); err != nil {
		return err
	}
	if err = m.verifyBlank(path); err == nil {
		return nil
	}
	info, err := m.run([]string{path}, "mdadm", "--examine", "--export", pin.Path())
	if err != nil {
		return err
	}
	for _, line := range strings.Fields(string(info)) {
		if value, ok := strings.CutPrefix(line, "MD_UUID="); ok && compactUUID(value) == compactUUID(uuid) {
			if _, err = m.run([]string{path}, "mdadm", "--zero-superblock", pin.Path()); err != nil {
				return err
			}
			_, err = m.run(nil, "udevadm", "settle")
			return err
		}
	}
	return reject("Array was stopped. Member metadata no longer identifies the reviewed array.")
}
