package accounts

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
)

const sharingInclude = "include = /etc/samba/panasms-shares.conf"
const sharingManaged = "# PaNasMs standalone file server\n[global]\nserver role = standalone server\nsecurity = user\nmap to guest = Never\nserver min protocol = SMB2_02\nobey pam restrictions = yes\nunix password sync = no\nload printers = no\ndisable spoolss = yes\nusershare max shares = 0\n" + sharingInclude + "\n"

func sharingConfig(shares []sharedFolder, pythonHook, legacyPermissions bool) (string, string) {
	var smb, nfs strings.Builder
	smb.WriteString(sharingHeader)
	nfs.WriteString(sharingHeader)
	for _, share := range shares {
		if share.SMB {
			fmt.Fprintf(&smb, "\n[%s]\npath = %s\nguest ok = no\nread only = yes\nvalid users = %s\nwrite list = %s\ncreate mask = 0660\ndirectory mask = 0770\ninherit permissions = no\nmap archive = no\nmap system = no\nmap hidden = no\nwide links = no\nfollow symlinks = no\n", share.Name, share.Path, strings.Join(append(append([]string{}, share.Readers...), share.Writers...), " "), strings.Join(share.Writers, " "))
			hook := "/usr/lib/panasms/panasms-system-helper sharing check "
			if pythonHook {
				hook = "/usr/bin/python3 /usr/lib/panasms/management/sharing.py --check "
			}
			smb.WriteString("root preexec = " + hook + share.Name + "\nroot preexec close = yes\n")
		}
		if share.SMB && share.NFS {
			smb.WriteString("oplocks = no\nlevel2 oplocks = no\nstrict locking = yes\n")
		}
		if share.NFS {
			nfs.WriteString(share.Path + " ")
			clients := []string{}
			mode := "rw"
			if share.ReadOnly {
				mode = "ro"
			}
			for _, client := range share.Clients {
				clients = append(clients, client+"("+mode+",sync,no_subtree_check,root_squash,mountpoint="+share.Mountpoint+")")
			}
			nfs.WriteString(strings.Join(clients, " ") + "\n")
		}
	}
	result := smb.String()
	if legacyPermissions {
		result = strings.ReplaceAll(result, "inherit permissions = no\nmap archive = no\nmap system = no\nmap hidden = no", "inherit permissions = yes")
	}
	return result, nfs.String()
}
func (s *sharingService) drift(st sharingState) (bool, error) {
	smb, nfs := sharingConfig(st.Shares, false, false)
	for path, want := range map[string]string{s.smb: smb, s.exports: nfs} {
		exists, err := sharingExists(path)
		if err != nil {
			return false, err
		}
		text, err := sharingText(path)
		if err != nil {
			return false, err
		}
		if exists && text != want || !exists && len(st.Shares) > 0 {
			return true, nil
		}
	}
	return false, nil
}
func (s *sharingService) check(ctx context.Context, share sharedFolder) error {
	row, err := s.locate(ctx, share.Path)
	if err != nil {
		return reject("Shared volume unavailable")
	}
	if sharingVolume(row) != share.Volume || row.Target != share.Mountpoint {
		return reject("Shared volume unavailable")
	}
	return nil
}
func (s *sharingService) validate(ctx context.Context, shares []sharedFolder, r *systemops.Reporter) error {
	previous, err := s.read()
	if err != nil {
		return err
	}
	for _, share := range shares {
		if share.SMB || share.NFS {
			if err := s.check(ctx, share); err != nil {
				if slices.ContainsFunc(previous.Shares, func(old sharedFolder) bool { return reflect.DeepEqual(old, share) }) {
					var inventory struct {
						Filesystems []struct{ Target string }
					}
					if e := s.jsonCommand(ctx, []string{"findmnt", "--json", "--list", "--output", "TARGET"}, &inventory); e != nil {
						return e
					}
					if !slices.ContainsFunc(inventory.Filesystems, func(row struct{ Target string }) bool { return row.Target == share.Mountpoint }) {
						if noLinks(share.Mountpoint) != nil {
							return err
						}
						continue
					}
				}
				return err
			}
		}
	}
	if !slices.ContainsFunc(shares, func(share sharedFolder) bool { return share.SMB }) {
		return nil
	}
	main, err := sharingText(s.mainConfig)
	if err != nil {
		return err
	}
	smb, _ := sharingConfig(shares, false, false)
	candidate, err := os.CreateTemp("", "panasms-smb-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(candidate.Name())
	_, err = candidate.WriteString(strings.ReplaceAll(main, sharingInclude, smb))
	closeErr := candidate.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	_, err = s.run(ctx, []string{"testparm", "-s", candidate.Name()}, systemops.CommandOptions{Timeout: 20 * time.Second, Reporter: r})
	return err
}
func (s *sharingService) reload(ctx context.Context, shares []sharedFolder, r *systemops.Reporter) error {
	if err := s.validate(ctx, shares, r); err != nil {
		return err
	}
	if s.tool("testparm") {
		if _, err := s.run(ctx, []string{"testparm", "-s"}, systemops.CommandOptions{Timeout: 20 * time.Second}); err != nil {
			return err
		}
		if !s.preserveServiceState && slices.ContainsFunc(shares, func(v sharedFolder) bool { return v.SMB }) {
			if _, err := s.command(ctx, []string{"systemctl", "enable", "--now", "smbd"}, true, r); err != nil {
				return err
			}
		}
		raw, err := s.run(ctx, []string{"systemctl", "is-active", "smbd"}, systemops.CommandOptions{Accepted: []int{0, 3, 4}})
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(raw)) == "active" {
			if _, err = s.command(ctx, []string{"smbcontrol", "all", "reload-config"}, true, r); err != nil {
				return err
			}
		}
	}
	if s.tool("exportfs") {
		if !s.preserveServiceState && slices.ContainsFunc(shares, func(v sharedFolder) bool { return v.NFS }) {
			if _, err := s.command(ctx, []string{"systemctl", "enable", "--now", "nfs-kernel-server"}, true, r); err != nil {
				return err
			}
		}
		if s.preserveServiceState {
			raw, err := s.run(ctx, []string{"systemctl", "is-active", "nfs-kernel-server"}, systemops.CommandOptions{Accepted: []int{0, 3, 4}})
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(raw)) != "active" {
				return nil
			}
		}
		if _, err := s.command(ctx, []string{"exportfs", "-ra"}, true, r); err != nil {
			return err
		}
	}
	return nil
}
func (s *sharingService) snapshot(extra bool) (map[string]string, error) {
	paths := []string{s.state, s.smb, s.exports}
	if extra {
		paths = append(paths, s.legacy)
	}
	old := map[string]string{}
	for _, path := range paths {
		text, err := sharingText(path)
		if err != nil {
			return nil, err
		}
		old[path] = text
	}
	return old, nil
}
func (s *sharingService) begin(extra bool) error {
	old, err := s.snapshot(extra)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(old)
	if err != nil {
		return err
	}
	return s.write(s.journal, string(raw), 0600)
}
func removeSharingFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (s *sharingService) rollback(ctx context.Context, r *systemops.Reporter) error {
	// Recovery must finish independently of the failed request's deadline.
	if err := s.recover(context.WithoutCancel(ctx), r); err != nil {
		return reject("Sharing update failed and rollback needs recovery. No data files were changed.")
	}
	return reject("Sharing update failed; previous configuration restored. Check service logs.")
}
func (s *sharingService) apply(ctx context.Context, st sharingState, r *systemops.Reporter) error {
	if err := validateSharingState(st); err != nil {
		return err
	}
	if err := s.validate(ctx, st.Shares, r); err != nil {
		return err
	}
	if err := s.begin(false); err != nil {
		return err
	}
	smb, nfs := sharingConfig(st.Shares, false, false)
	if err := s.write(s.smb, smb, 0644); err != nil {
		return s.rollback(ctx, r)
	}
	if err := s.write(s.exports, nfs, 0644); err != nil {
		return s.rollback(ctx, r)
	}
	if err := s.reload(ctx, st.Shares, r); err != nil {
		return s.rollback(ctx, r)
	}
	if err := s.save(st); err != nil {
		return s.rollback(ctx, r)
	}
	return removeSharingFile(s.journal)
}
func (s *sharingService) recover(ctx context.Context, r *systemops.Reporter) error {
	pending, err := sharingExists(s.journal)
	if err != nil {
		return err
	}
	if pending {
		raw, err := os.ReadFile(s.journal)
		if err != nil {
			return err
		}
		var old map[string]string
		if err = systemops.Decode(raw, &old); err != nil {
			return err
		}
		if len(old) != 3 && len(old) != 4 {
			return reject("Invalid sharing recovery journal; configuration was preserved")
		}
		for _, path := range []string{s.state, s.smb, s.exports} {
			if _, ok := old[path]; !ok {
				return reject("Invalid sharing recovery journal; configuration was preserved")
			}
		}
		for path := range old {
			if !slices.Contains([]string{s.state, s.smb, s.exports, s.legacy}, path) {
				return reject("Invalid sharing recovery journal; configuration was preserved")
			}
		}
		if old[s.state] != "" {
			var previous sharingState
			if err = systemops.Decode([]byte(old[s.state]), &previous); err != nil {
				return err
			}
			if err = validateSharingState(previous); err != nil {
				return err
			}
		}
		for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
			value, ok := old[path]
			if !ok {
				continue
			}
			if value == "" {
				err = removeSharingFile(path)
			} else {
				mode := os.FileMode(0644)
				if path == s.state {
					mode = 0600
				}
				err = s.write(path, value, mode)
			}
			if err != nil {
				return err
			}
		}
		st, err := s.read()
		if err != nil {
			return err
		}
		if err = s.reload(ctx, st.Shares, r); err != nil {
			return err
		}
		return removeSharingFile(s.journal)
	}
	st, err := s.read()
	if err != nil {
		return err
	}
	return s.apply(ctx, st, r)
}
func (s *sharingService) republish(ctx context.Context) error {
	previous := s.preserveServiceState
	s.preserveServiceState = true
	defer func() { s.preserveServiceState = previous }()
	st, err := s.read()
	if err != nil {
		return err
	}
	pending, err := sharingExists(s.journal)
	if err != nil {
		return err
	}
	if len(st.Shares) == 0 || pending {
		return nil
	}
	currentSMB, err := sharingText(s.smb)
	if err != nil {
		return err
	}
	currentNFS, err := sharingText(s.exports)
	if err != nil {
		return err
	}
	for _, python := range []bool{true, false} {
		for _, legacy := range []bool{true, false} {
			smb, nfs := sharingConfig(st.Shares, python, legacy)
			if currentSMB == smb && currentNFS == nfs {
				if !python && !legacy {
					return nil
				}
				return s.apply(ctx, st, nil)
			}
		}
	}
	if (currentSMB == "" || currentSMB == sharingHeader) && (currentNFS == "" || currentNFS == sharingHeader) {
		return s.apply(ctx, st, nil)
	}
	return nil
}
func (s *sharingService) removeShares(ctx context.Context, names []string) ([]sharedFolder, error) {
	unlock, err := s.locked()
	if err != nil {
		return nil, err
	}
	defer unlock()
	pending, err := sharingExists(s.journal)
	if err != nil {
		return nil, err
	}
	if pending {
		return nil, reject(sharingPending)
	}
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	changed, err := s.drift(st)
	if err != nil {
		return nil, err
	}
	if changed {
		return nil, reject(sharingDrift)
	}
	removed := []sharedFolder{}
	kept := []sharedFolder{}
	for _, share := range st.Shares {
		if !slices.Contains(names, share.Name) {
			kept = append(kept, share)
			continue
		}
		removed = append(removed, share)
		if s.tool("smbcontrol") {
			if _, err = s.run(ctx, []string{"smbcontrol", "smbd", "close-share", share.Name}, systemops.CommandOptions{Accepted: []int{0, 1}, Operation: true}); err != nil {
				return nil, err
			}
		}
	}
	if len(removed) > 0 {
		st.Shares = kept
		if err = s.apply(ctx, st, nil); err != nil {
			return nil, err
		}
	}
	return removed, nil
}
func (s *sharingService) install(ctx context.Context) error {
	marker := filepath.Join(s.installer, "sharing-installed")
	saved := filepath.Join(s.installer, "smb.conf.before-sharing")
	if err := os.MkdirAll(s.installer, 0700); err != nil {
		return err
	}
	exists, err := sharingExists(marker)
	if err != nil {
		return err
	}
	if !exists {
		original, err := sharingText(s.mainConfig)
		if err != nil {
			return err
		}
		present, err := sharingExists(s.mainConfig)
		if err != nil {
			return err
		}
		vendor, err := os.ReadFile(s.vendor)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		pristine := !present || (err == nil && bytes.Equal(vendor, []byte(original)))
		if !pristine {
			raw, e := s.run(ctx, []string{"dpkg-query", "-W", "-f=${Conffiles}", "samba-common"}, systemops.CommandOptions{})
			if e != nil {
				return e
			}
			sum := md5.Sum([]byte(original))
			for _, line := range strings.Split(string(raw), "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && f[0] == s.mainConfig && f[1] == hex.EncodeToString(sum[:]) {
					pristine = true
				}
			}
		}
		if pristine {
			if present {
				if err = s.write(saved, original, 0644); err != nil {
					return err
				}
			}
			if err = s.write(s.mainConfig, sharingManaged, 0644); err != nil {
				return err
			}
			if err = s.write(marker, sharingManaged, 0600); err != nil {
				return err
			}
		} else {
			fmt.Fprintln(os.Stderr, "Existing Samba configuration preserved. Add "+sharingInclude+" to smb.conf after review to enable managed SMB shares.")
		}
	}
	exists, err = sharingExists(s.smb)
	if err != nil {
		return err
	}
	if !exists {
		if err = s.write(s.smb, sharingHeader, 0644); err != nil {
			return err
		}
	}
	_, err = s.run(ctx, []string{"testparm", "-s"}, systemops.CommandOptions{})
	return err
}
func (s *sharingService) removeInstallation() error {
	marker := filepath.Join(s.installer, "sharing-installed")
	managed, err := sharingText(marker)
	if err != nil {
		return err
	}
	current, err := sharingText(s.mainConfig)
	if err != nil {
		return err
	}
	if managed != "" && current == managed {
		saved := filepath.Join(s.installer, "smb.conf.before-sharing")
		exists, err := sharingExists(saved)
		if err != nil {
			return err
		}
		if exists {
			text, err := sharingText(saved)
			if err != nil {
				return err
			}
			if err = s.write(s.mainConfig, text, 0644); err != nil {
				return err
			}
		}
	}
	return removeSharingFile(marker)
}

func (s *sharingService) prepareDowngrade(ctx context.Context) error {
	if s.pendingRollback {
		var ticket sharingActivationTicket
		present, err := s.metadata(s.activationTicket, &ticket)
		if err != nil || !present || s.validTicket(&ticket) != nil {
			return reject(sharingActivationPending)
		}
		if !ticket.Source.Native {
			return nil
		}
		return s.preparePendingNativeHooks(ctx, ticket)
	}
	if _, err := s.rollbackWitnessLocked(); err != nil {
		return err
	}
	current, err := sharingText(s.smb)
	if err != nil {
		return err
	}
	if !strings.Contains(current, "root preexec = /usr/lib/panasms/panasms-system-helper sharing check ") {
		return nil
	}
	st, err := s.read()
	if err != nil {
		return err
	}
	changed, err := s.drift(st)
	if err != nil {
		return err
	}
	if changed {
		return reject(sharingDrift)
	}
	entry, err := s.fileSnapshot(s.smb)
	if err != nil {
		return err
	}
	smb, _ := sharingConfig(st.Shares, true, false)
	if err = s.writeHookConversion(entry, smb); err != nil {
		return err
	}
	return s.reloadActiveSMB(ctx)
}

func (s *sharingService) preparePendingNativeHooks(ctx context.Context, ticket sharingActivationTicket) error {
	var baseline sharingState
	if err := systemops.Decode(ticket.Files[s.state].Data, &baseline); err != nil {
		return err
	}
	if !s.knownSharingConfig(ticket.Files, baseline) {
		return reject(sharingDrift)
	}
	before := ticket.Files[s.smb]
	converted := before
	converted.Data = bytes.ReplaceAll(before.Data, []byte("root preexec = /usr/lib/panasms/panasms-system-helper sharing check "), []byte("root preexec = /usr/bin/python3 /usr/lib/panasms/management/sharing.py --check "))
	if sharingSnapshotsEqual(before, converted) {
		return nil
	}
	current, err := s.fileSnapshot(s.smb)
	if err != nil {
		return err
	}
	if sharingSnapshotsEqual(current, before) {
		if err = s.writeHookConversion(current, string(converted.Data)); err != nil {
			return err
		}
	} else if !sharingSnapshotsEqual(current, converted) {
		return reject(sharingDrift)
	}
	return s.reloadActiveSMB(ctx)
}

func (s *sharingService) reloadActiveSMB(ctx context.Context) error {
	if s.tool("smbcontrol") {
		raw, err := s.run(ctx, []string{"systemctl", "is-active", "smbd"}, systemops.CommandOptions{Accepted: []int{0, 3, 4}})
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(raw)) == "active" {
			_, err = s.run(ctx, []string{"smbcontrol", "all", "reload-config"}, systemops.CommandOptions{})
			return err
		}
	}
	return nil
}
