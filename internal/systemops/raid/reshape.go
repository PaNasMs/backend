package raid

import (
	"context"
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

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/disksleep"
	"panasms.local/backend/internal/systemops/storagebase"
)

type reshapeRecord struct {
	UUID        string `json:"uuid"`
	Target      string `json:"target"`
	Level       string `json:"level"`
	Members     int    `json:"members"`
	SourceCount int    `json:"sourceCount,omitempty"`
	Backup      string `json:"backup"`
	Growth      bool   `json:"growth,omitempty"`
}

func (s *service) backup(uuid string) string {
	return filepath.Join(s.reshapeRoot, strings.ReplaceAll(uuid, ":", "-")+".backup")
}
func recordPath(backup string) string { return strings.TrimSuffix(backup, ".backup") + ".json" }

// The legacy record names and UUID spelling must survive upgrades.
func (s *service) record(uuid string) (*reshapeRecord, error) {
	if !uuidPattern.MatchString(uuid) {
		return nil, reject("Invalid RAID UUID")
	}
	if err := storagebase.SecureDirectory(s.reshapeRoot, s.owner, false); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	// Both kernel and mdadm UUID spellings have been persisted by older workers.
	rawUUID := compactUUID(uuid)
	candidates := []string{strings.Join([]string{rawUUID[:8], rawUUID[8:12], rawUUID[12:16], rawUUID[16:20], rawUUID[20:]}, "-"), strings.Join([]string{rawUUID[:8], rawUUID[8:16], rawUUID[16:24], rawUUID[24:]}, ":")}
	var backup, path string
	var st os.FileInfo
	for _, form := range candidates {
		candidate := s.backup(form)
		info, e := os.Lstat(recordPath(candidate))
		if os.IsNotExist(e) {
			if exists, e := backupPresent(candidate, s.owner); e != nil {
				return nil, e
			} else if exists {
				return nil, reject("RAID backup has no matching recovery record")
			}
			continue
		}
		if e != nil {
			return nil, e
		}
		if st != nil {
			return nil, reject("Ambiguous RAID recovery record")
		}
		st = info
		backup = candidate
		path = recordPath(candidate)
	}
	if st == nil {
		return nil, nil
	}
	if !st.Mode().IsRegular() || st.Sys().(*syscall.Stat_t).Nlink != 1 || st.Mode().Perm()&0022 != 0 || int(st.Sys().(*syscall.Stat_t).Uid) != s.owner || st.Size() > 65536 {
		return nil, reject("Invalid RAID recovery record")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec reshapeRecord
	if err = json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if !uuidPattern.MatchString(rec.UUID) || compactUUID(rec.UUID) != compactUUID(uuid) || s.backup(rec.UUID) != backup || rec.Backup != backup || (rec.Level != "5" && rec.Level != "6") || rec.Members < 3 || rec.Members > 4096 || rec.SourceCount < 0 || rec.SourceCount > 4096 || (rec.SourceCount != 0 && rec.SourceCount != rec.Members-1 && rec.SourceCount != rec.Members+1) {
		return nil, reject("RAID recovery record does not match this array")
	}
	if _, err = backupPresent(backup, s.owner); err != nil {
		return nil, err
	}
	return &rec, nil
}

func backupPresent(path string, owner int) (bool, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !st.Mode().IsRegular() || st.Sys().(*syscall.Stat_t).Nlink != 1 || int(st.Sys().(*syscall.Stat_t).Uid) != owner || st.Mode().Perm()&0022 != 0 {
		return false, reject("Unsafe RAID recovery file")
	}
	return true, nil
}

func (s *service) conversionBackup(ctx context.Context, p *prepared) error {
	a := p.State
	rec, err := s.record(a.UUID)
	if err != nil {
		return err
	}
	backup := s.backup(a.UUID)
	if rec != nil {
		backup = rec.Backup
	}
	present, err := backupPresent(backup, s.owner)
	if err != nil {
		return err
	}
	if present {
		if rec == nil || a.Level != "raid"+rec.Level || a.Count != rec.Members {
			return reject("Verify the previous RAID conversion before starting another one")
		}
	}
	p.Record = rec
	dir := s.reshapeRoot
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		dir = filepath.Dir(dir)
	}
	source, err := s.run(ctx, []string{"findmnt", "-n", "-o", "MAJ:MIN", "-T", dir}, systemops.CommandOptions{})
	if err != nil {
		return err
	}
	node, err := filepath.EvalSymlinks(filepath.Join("/sys/dev/block", strings.TrimSpace(string(source))))
	if err != nil {
		return err
	}
	used, err := usesArray(node, filepath.Base(p.Target), map[string]bool{})
	if err != nil {
		return err
	}
	if used {
		return reject("RAID recovery data must be stored outside the array being changed")
	}
	var st syscall.Statfs_t
	if err = syscall.Statfs(dir, &st); err != nil {
		return err
	}
	// Adjacent member counts are coprime, so their product is the least common multiple.
	stripe := uint64(a.Count) * uint64(p.NewCount) * 4
	chunk := max(a.Chunk, uint64(65536))
	free := st.Bavail * uint64(st.Bsize)
	if free <= 128<<20 || chunk >= (free/2)/stripe {
		return reject("Not enough free space on the system disk for RAID recovery data")
	}
	return nil
}

func usesArray(node, target string, seen map[string]bool) (bool, error) {
	if filepath.Base(node) == target {
		return true, nil
	}
	if seen[node] {
		return false, nil
	}
	seen[node] = true
	if _, err := os.Stat(filepath.Join(node, "partition")); err == nil {
		return usesArray(filepath.Dir(node), target, seen)
	} else if !os.IsNotExist(err) {
		return false, err
	}
	children, err := os.ReadDir(filepath.Join(node, "slaves"))
	if err != nil {
		return false, err
	}
	for _, c := range children {
		p, err := filepath.EvalSymlinks(filepath.Join(node, "slaves", c.Name()))
		if err != nil {
			return false, err
		}
		used, err := usesArray(p, target, seen)
		if used || err != nil {
			return used, err
		}
	}
	return false, nil
}

func safeResume(a *arrayState, rec *reshapeRecord) bool {
	if rec == nil {
		return a.Degraded == 0 && a.Sync == "frozen" && a.Array != "readonly" && a.Array != "read-auto"
	}
	if compactUUID(a.UUID) != compactUUID(rec.UUID) {
		return false
	}
	if a.Degraded == 0 {
		return true
	}
	if len(a.Members) != rec.Members {
		return false
	}
	count := rec.SourceCount
	if count == 0 {
		count = rec.Members
	}
	slots := map[int]bool{}
	for _, m := range a.Members {
		if badMember(m) {
			return false
		}
		if slices.Contains(m.State, "in_sync") {
			n, err := strconv.Atoi(m.Slot)
			if err != nil || n < 0 || slots[n] {
				return false
			}
			slots[n] = true
		}
	}
	for i := 0; i < count; i++ {
		if !slots[i] {
			return false
		}
	}
	return true
}

func scoped(op string, args ...string) []string {
	return append([]string{"systemd-run", "--scope", "--quiet", fmt.Sprintf("--unit=panasms-raid-%s-%d", op, time.Now().UnixNano()), "/usr/sbin/mdadm"}, args...)
}

func (s *service) resume(ctx context.Context, target string, a *arrayState, rec *reshapeRecord, r *systemops.Reporter) error {
	if !a.Reshaping || (a.Sync != "idle" && a.Sync != "frozen") || !safeResume(a, rec) || slices.Contains([]string{"clear", "inactive", "suspended"}, a.Array) {
		return reject("The array is not ready to resume reshape")
	}
	opts := systemops.CommandOptions{Operation: true, Reporter: r}
	if (a.Array == "read-auto" || a.Array == "readonly") && (rec == nil || a.Sync == "frozen") {
		if _, err := s.run(ctx, []string{"mdadm", "--readwrite", target}, opts); err != nil {
			return err
		}
	}
	md := filepath.Join(s.sys, filepath.Base(target), "md")
	fresh, err := s.readArray(filepath.Base(target))
	if err != nil {
		return err
	}
	if fresh.UUID != a.UUID {
		return reject("RAID identity changed")
	}
	if !fresh.Reshaping || fresh.Sync == "reshape" {
		return nil
	}
	if !safeResume(fresh, rec) {
		return reject("Recover missing or failed array members first")
	}
	switch fresh.Sync {
	case "frozen":
		err = os.WriteFile(filepath.Join(md, "sync_action"), []byte("reshape"), 0)
	case "idle":
		args := []string{"--grow", target, "--continue"}
		if rec != nil && !rec.Growth {
			present, e := backupPresent(rec.Backup, s.owner)
			if e != nil {
				return e
			}
			if present {
				args = append(args, "--backup-file="+rec.Backup)
			}
		}
		_, err = s.run(ctx, scoped("resume", args...), opts)
	default:
		return reject("Array maintenance changed before resuming reshape")
	}
	if err != nil {
		return err
	}
	for i := 0; i < 30; i++ {
		fresh, err := s.readArray(filepath.Base(target))
		if err != nil {
			return err
		}
		if fresh.UUID != a.UUID {
			return reject("RAID identity changed")
		}
		if !fresh.Reshaping || fresh.Sync == "reshape" {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return reject("Could not confirm reshape resumption. Refresh array state and check the system journal.")
}

// Package removal only inspects. Boot may assemble by recorded UUID and continue an
// existing reshape; a record alone is never evidence to start a new conversion.
func RecoveryCommand(ctx context.Context, boot bool) error {
	lock, err := storagebase.DomainLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	return disksleep.WithStorageLock(func() error { return defaultService().recoverRecords(ctx, boot) })
}

func (s *service) recoverRecords(ctx context.Context, boot bool) error {
	intents, err := readIntents()
	if err != nil {
		return err
	}
	if !boot && len(intents) > 0 {
		return reject("Inspect the pending RAID lifecycle journals before removing PaNasMs")
	}
	err = storagebase.SecureDirectory(s.reshapeRoot, s.owner, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(s.reshapeRoot)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if slices.ContainsFunc(intents, func(j *intent) bool { return j.blocks(strings.TrimSuffix(entry.Name(), ".json")) }) {
			continue
		}
		if err = s.recoverRecord(ctx, entry.Name(), boot); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", entry.Name(), err))
		}
	}
	return errors.Join(failures...)
}

func (s *service) recoverRecord(ctx context.Context, name string, boot bool) error {
	uuid := strings.TrimSuffix(name, ".json")
	if !uuidPattern.MatchString(uuid) {
		uuid = strings.ReplaceAll(uuid, "-", ":")
	}
	rec, err := s.record(uuid)
	if err != nil {
		return err
	}
	if rec == nil || filepath.Base(recordPath(rec.Backup)) != name {
		return reject("Missing RAID recovery record")
	}
	entries, err := os.ReadDir(s.sys)
	if err != nil {
		return err
	}
	target := ""
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.sys, entry.Name(), "md", "uuid"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if compactUUID(strings.TrimSpace(string(b))) == compactUUID(uuid) {
			if target != "" {
				return reject("Ambiguous RAID UUID")
			}
			target = "/dev/" + entry.Name()
		}
	}
	if target == "" {
		if !boot {
			return reject("Finish or recover the RAID conversion before removing PaNasMs")
		}
		path := "/dev/md/panasms-recover-" + compactUUID(uuid)[:16]
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			return reject("RAID recovery name is occupied")
		}
		args := []string{"mdadm", "--assemble", path, "--uuid=" + uuid}
		present, err := backupPresent(rec.Backup, s.owner)
		if err != nil {
			return err
		}
		// mdadm 4.4 backups for interrupted RAID5/6 restripes can contain
		// incorrect logical data. Preserve the original members for recovery.
		if present && !rec.Growth && (rec.Level == "6" || rec.SourceCount > rec.Members || rec.SourceCount == 0) {
			return reject("RAID conversion backup present. Preserve the member disks and backup for offline recovery before assembling this array.")
		}
		if present {
			args = append(args, "--backup-file="+rec.Backup)
		}
		if _, err = s.run(ctx, args, systemops.CommandOptions{Operation: true}); err != nil {
			return err
		}
		target, err = s.resolve(path)
		if err != nil {
			return err
		}
	}
	a, err := s.readArray(filepath.Base(target))
	if err != nil {
		return err
	}
	if compactUUID(a.UUID) != compactUUID(uuid) {
		return reject("RAID identity changed")
	}
	if !a.Reshaping {
		present, err := backupPresent(rec.Backup, s.owner)
		if err != nil {
			return err
		}
		if present && (a.Level != "raid"+rec.Level || a.Count != rec.Members) || (!boot && a.Sync != "idle") {
			return reject("Finish or recover the RAID conversion before removing PaNasMs")
		}
		return nil
	}
	if !boot {
		return reject("Finish or recover the RAID conversion before removing PaNasMs")
	}
	if a.Sync == "reshape" {
		return nil
	}
	return s.resume(ctx, target, a, rec, nil)
}
func compactUUID(uuid string) string {
	return strings.ToLower(strings.NewReplacer(":", "", "-", "").Replace(uuid))
}
