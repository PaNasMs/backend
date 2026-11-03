package localmounts

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"os/user"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

func reject(message string) error              { return &systemops.Rejected{Message: message} }
func text(p map[string]any, key string) string { v, _ := p[key].(string); return v }
func IsAction(action string) bool {
	return slices.Contains([]string{"disk.prepare", "disk.eject", "mount.attach", "mount.detach", "mount.open", "mount.settings"}, action)
}

type service struct {
	stageRoot string
	sys, root string
	owner     int
	load      func(context.Context) (*storagequery.Preflight, error)
	identity  func(*storagequery.Preflight, string) (storagequery.StorageIdentity, error)
	resolve   func(string) (string, error)
	mounts    func() ([]folders.LiveMount, error)
	fstab     func() (string, error)
	witness   func(string) (storagebase.TargetWitness, error)
	blockers  func(context.Context, []folders.LiveMount, []folders.LiveMount) error
	user      func(string) (*user.User, error)
	group     func(string) (*user.Group, error)
	tool      func(string) bool
	run       func(context.Context, []string, systemops.CommandOptions) ([]byte, error)
}

func defaultService() *service {
	return &service{
		stageRoot: "/run/panasms-local-mounts", sys: "/sys/class/block", root: "/var/lib/panasms-agent/local-mounts", load: storagequery.LoadPreflight,
		identity: func(p *storagequery.Preflight, target string) (storagequery.StorageIdentity, error) {
			return p.Identity(target)
		},
		resolve: filepath.EvalSymlinks, mounts: folders.ReadMounts, fstab: storagebase.ReadFstab,
		witness: func(point string) (storagebase.TargetWitness, error) {
			w, f, err := storagebase.ObserveTarget(point)
			if f != nil {
				f.Close()
			}
			return w, err
		},
		user: user.Lookup, group: user.LookupGroup, tool: func(name string) bool { _, err := exec.LookPath(name); return err == nil }, run: systemops.Command,
		blockers: defaultBlockers,
	}
}

type plan struct {
	prior                                         *transaction
	stale                                         *folders.LiveMount
	remountParent                                 *storagebase.TargetWitness
	target, point, fs, options, conf, fingerprint string
	journalRevision                               string
	preflight                                     *storagequery.Preflight
	identities                                    map[string]storagequery.StorageIdentity
	mounts, selected                              []folders.LiveMount
	witness                                       storagebase.TargetWitness
	details                                       []string
}

func Plan(ctx context.Context, action string, p map[string]any, actor string) (json.RawMessage, error) {
	v, err := defaultService().prepare(ctx, action, p, actor)
	if err != nil {
		return nil, err
	}
	return v.public()
}
func (v *plan) public() (json.RawMessage, error) {
	return json.Marshal(map[string]any{"target": v.target, "confirmation": v.target, "details": v.details, "fingerprint": v.fingerprint})
}
func MountPolicy(p map[string]any) (string, error) {
	policy := text(p, "mountPolicy")
	if policy == "" {
		policy = "manual"
		if p["automount"] == true {
			policy = "boot"
		}
	}
	if !slices.Contains([]string{"manual", "boot", "on-demand"}, policy) {
		return "", reject("Unknown automatic mount policy")
	}
	return policy, nil
}
func MountOptions(p map[string]any) (string, error) {
	policy, err := MountPolicy(p)
	if err != nil {
		return "", err
	}
	mode := "rw"
	readOnly := p["readOnly"] == true
	if mode := text(p, "mode"); mode == "readonly" {
		readOnly = true
	} else if mode == "repair" || mode == "repair-only" {
		readOnly = false
	}
	if readOnly {
		mode = "ro"
	}
	opts := mode + ",noatime,nofail,x-systemd.device-timeout=30s"
	if policy == "manual" {
		opts += ",noauto"
	} else if policy == "on-demand" {
		opts += ",x-systemd.automount,x-systemd.idle-timeout=10min"
	}
	return opts, nil
}
func within(path, point string) bool {
	return path == point || strings.HasPrefix(path, strings.TrimRight(point, "/")+"/")
}
func verifyConfigOwners(pf *storagequery.Preflight, uuids []string, allowed func(string) bool) error {
	if len(uuids) == 0 {
		return nil
	}
	for path, row := range pf.Inventory.Rows {
		if !allowed(path) && slices.Contains(uuids, text(row, "uuid")) {
			return reject("This file system UUID is present on another device. Review the mount configuration.")
		}
	}
	return nil
}

func (s *service) prepare(ctx context.Context, action string, p map[string]any, actor string) (*plan, error) {
	if !IsAction(action) {
		return nil, reject("Unknown storage operation")
	}
	if !strings.HasPrefix(text(p, "target"), "/dev/") {
		return nil, reject("Select a block device")
	}
	target, err := s.resolve(text(p, "target"))
	if err != nil {
		return nil, reject("The device no longer exists")
	}
	pf, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	row := pf.Inventory.Rows[target]
	if row == nil {
		return nil, reject("The device no longer exists")
	}
	if err = pf.Protected(target, false); err != nil {
		return nil, err
	}
	all, err := s.mounts()
	if err != nil {
		return nil, err
	}
	conf, err := s.fstab()
	if err != nil {
		return nil, err
	}
	v := &plan{target: target, fs: text(row, "fstype"), conf: conf, preflight: pf, mounts: all, identities: map[string]storagequery.StorageIdentity{}}
	prior, revision, err := readJournal(s.root, target, s.owner)
	if err != nil {
		return nil, err
	}
	v.prior = prior
	v.journalRevision = revision
	numbers := map[string]bool{}
	observed := map[string]storagequery.DeviceIdentity{}
	boot := ""
	for _, path := range pf.Inventory.Descendants(target) {
		identity, err := s.identity(pf, path)
		if err != nil {
			return nil, err
		}
		if boot != "" && boot != identity.BootID {
			return nil, reject("Storage identity changed during inspection")
		}
		boot = identity.BootID
		for _, entry := range identity.Devices {
			if old, ok := observed[entry.Path]; ok && old != entry {
				return nil, reject("Storage identity changed during inspection")
			}
			observed[entry.Path] = entry
		}
		v.identities[path] = identity
		for _, dev := range identity.Devices {
			if dev.Path == path {
				numbers[dev.DeviceNumber] = true
			}
		}
	}
	for _, m := range all {
		selected := numbers[m.Device]
		if !selected && m.FSType == "btrfs" {
			for path := range v.identities {
				child := pf.Inventory.Rows[path]
				if text(child, "fstype") != "btrfs" || !mountedPoint(child, m.Target) {
					continue
				}
				if err = verifyBtrfsPoint(m.Target, path, text(child, "uuid")); err != nil {
					return nil, err
				}
				selected = true
				break
			}
		}
		if selected {
			if err = folders.MountPath(m.Target); err != nil {
				if action != "mount.detach" || prior == nil || prior.Phase != "pending" || !prior.StageIntent || m.Target != s.privateStage(target) || prior.Stage != m.Target {
					return nil, err
				}
			}
			v.selected = append(v.selected, m)
		}
	}
	sort.Slice(v.selected, func(i, j int) bool {
		if len(v.selected[i].Target) == len(v.selected[j].Target) {
			return v.selected[i].Target < v.selected[j].Target
		}
		return len(v.selected[i].Target) > len(v.selected[j].Target)
	})
	switch action {
	case "disk.prepare":
		if err = s.checkPrepareSources(v.conf, pf, v.identities); err != nil {
			return nil, err
		}
		desired, err := desiredFstab(action, v)
		if err != nil {
			return nil, err
		}
		removed := storagebase.RemovedFstabUUIDs(v.conf, desired)
		if err = verifyConfigOwners(pf, removed, func(path string) bool { _, selected := v.identities[path]; return selected }); err != nil {
			return nil, err
		}
		if err = pf.Unused(target, true); err != nil {
			return nil, err
		}
		if len(v.selected) > 0 {
			return nil, reject("Unmount file systems first")
		}
		if !slices.Contains([]string{"disk", "part", "loop"}, text(row, "type")) {
			return nil, reject("Select a standalone disk or partition")
		}
		v.details = []string{target, "PARTITION TABLE AND SIGNATURES WILL BE REMOVED; DATA WILL BECOME INACCESSIBLE", "This does not fully erase the drive's contents"}
	case "disk.eject":
		if text(row, "type") != "disk" {
			return nil, reject("Select a physical drive")
		}
		if _, err = os.Stat(filepath.Join(s.sys, text(row, "kname"), "device/delete")); err != nil {
			return nil, reject("The controller does not support disconnection")
		}
		for _, path := range pf.Inventory.Descendants(target) {
			child := pf.Inventory.Rows[path]
			if !slices.Contains([]string{"disk", "part"}, text(child, "type")) {
				return nil, reject("The drive is used by an array or another storage layer")
			}
			holders, err := pf.Holders(text(child, "kname"))
			if err != nil {
				return nil, reject("Could not verify storage dependencies. No changes were made.")
			}
			if len(holders) > 0 {
				return nil, reject("Device " + path + " is used by: " + strings.Join(holders, ", "))
			}
		}
		if err = s.blockers(ctx, v.selected, all); err != nil {
			return nil, err
		}
		v.details = []string{target, "All mounted drive volumes will be unmounted, pending writes saved, and the device disconnected"}
		for _, m := range v.selected {
			v.details = append(v.details, m.Target)
		}
	case "mount.detach":
		if len(v.selected) == 0 {
			if prior == nil || prior.Phase != "pending" || (!prior.StageIntent && prior.MountID == 0) {
				return nil, reject("Device is not mounted")
			}
			if prior.MountID != 0 && prior.Identity.BootID == boot {
				for _, live := range all {
					if live.ID != prior.MountID {
						continue
					}
					// Mount IDs can be reused. Only retain evidence of the recorded volume.
					for _, device := range prior.Identity.Devices {
						if device.Path != prior.Target {
							continue
						}
						matches := live.Device == device.DeviceNumber
						if live.FSType == "btrfs" && prior.FSType == "btrfs" {
							mountedUUID, err := recordedBtrfsUUID(live)
							if err != nil {
								return nil, err
							}
							matches = device.UUID == "" || strings.EqualFold(mountedUUID, device.UUID)
						}
						if matches {
							return nil, reject("The mount changed; review a new operation plan")
						}
					}
				}
			}
		}
		if err = s.blockers(ctx, v.selected, all); err != nil {
			return nil, err
		}
		v.details = []string{target, "The volume will be unmounted without forcibly terminating processes"}
		if len(v.selected) == 0 {
			v.details = []string{target, "Clear the interrupted mount state after verifying that the mount is gone."}
		}
	default:
		if v.fs == "" || slices.Contains([]string{"linux_raid_member", "crypto_LUKS", "swap"}, v.fs) {
			return nil, reject("Select a file system")
		}
		v.point = text(p, "point")
		if err = folders.MountPath(v.point); err != nil {
			return nil, err
		}
		if strings.ContainsAny(v.point, "\n\r") {
			return nil, reject("Invalid mount point")
		}
		v.witness, err = s.witness(v.point)
		if err != nil {
			return nil, err
		}
		occupied, ours := false, false
		var occupiedMount folders.LiveMount
		for _, m := range all {
			if m.Target == v.point {
				occupied = true
				occupiedMount = m
				for _, selected := range v.selected {
					ours = ours || selected.ID == m.ID
				}
			}
		}
		if occupied && !ours {
			if action != "mount.open" || len(v.selected) > 0 || !staleBlockMount(occupiedMount) {
				return nil, reject("The mount point is already used by another volume")
			}
			v.stale = &occupiedMount
			if err = s.blockers(ctx, []folders.LiveMount{occupiedMount}, all); err != nil {
				return nil, err
			}
			parent, err := trustedRemountParent(v.point)
			if err != nil {
				return nil, err
			}
			v.remountParent = &parent
		}
		if action == "mount.attach" && len(v.selected) > 0 {
			return nil, reject("Already mounted")
		}
		if !ours && v.stale == nil && v.witness.Ancestor == v.point {
			f, err := folders.OpenDirectory(v.point)
			if err != nil {
				return nil, err
			}
			names, readErr := f.Readdirnames(1)
			f.Close()
			if len(names) > 0 {
				return nil, reject("The mount point directory must be empty")
			}
			if readErr != nil && readErr != io.EOF {
				return nil, readErr
			}
		}
		if text(row, "uuid") == "" {
			return nil, reject("A UUID is required for mounting")
		}
		if action != "mount.open" || text(p, "mode") != "repair-only" {
			if err = verifyConfigOwners(pf, []string{text(row, "uuid")}, func(path string) bool { return path == target }); err != nil {
				return nil, err
			}
		}
		policy, err := MountPolicy(p)
		if err != nil {
			return nil, err
		}
		v.options, err = MountOptions(p)
		if err != nil {
			return nil, err
		}
		if action == "mount.open" {
			changesMount := text(p, "mode") == "repair" || text(p, "mode") == "repair-only"
			for _, m := range v.selected {
				changesMount = changesMount || (strings.HasPrefix(v.options, "ro,") && !strings.Contains(","+m.Options+",", ",ro,"))
			}
			if ours && changesMount {
				parent, err := trustedRemountParent(v.point)
				if err != nil {
					return nil, err
				}
				v.remountParent = &parent
			}
			mode := text(p, "mode")
			if mode == "" {
				mode = "auto"
			}
			if !slices.Contains([]string{"auto", "repair", "repair-only", "readonly"}, mode) {
				return nil, reject("Unknown mount mode")
			}
			if !slices.Contains([]string{"disk", "part"}, text(row, "type")) {
				return nil, reject("Select a removable drive partition")
			}
			if mode == "repair-only" && len(v.selected) > 0 {
				return nil, reject("Volume already mounted. Unmount it before repairing.")
			}
			if mode == "repair" || mode == "repair-only" {
				if !s.checkAvailable(v.fs) {
					return nil, reject("Automatic repair is unavailable for this file system")
				}
				if err = s.blockers(ctx, v.selected, all); err != nil {
					return nil, err
				}
			}
		}
		if slices.Contains([]string{"vfat", "exfat", "ntfs", "ntfs3"}, v.fs) {
			u, err := s.user(actor)
			if err != nil {
				return nil, reject("No user specified for mounting the volume")
			}
			g, err := s.group("users")
			if err != nil {
				return nil, err
			}
			uid, err := strconv.ParseUint(u.Uid, 10, 32)
			if err != nil {
				return nil, err
			}
			gid, err := strconv.ParseUint(g.Gid, 10, 32)
			if err != nil {
				return nil, err
			}
			v.options += ",uid=" + strconv.FormatUint(uid, 10) + ",gid=" + strconv.FormatUint(gid, 10) + ",fmask=0113,dmask=0002"
		}
		if strings.HasPrefix(v.options, "ro,") && slices.Contains([]string{"ext3", "ext4"}, v.fs) {
			v.options += ",noload"
		}
		descriptions := map[string]string{"manual": "Manual mounting; remember this mount point without mounting at startup.", "boot": "Mount at startup; a missing device will not block boot.", "on-demand": "Mount on first access after startup; unmount after 10 idle minutes when not busy."}
		v.details = []string{target, v.point, descriptions[policy]}
		if action == "mount.settings" {
			v.details = append(v.details, "Changes to automatic mounting take effect at the next startup. The current mount is unchanged.")
		}
	}
	if prior != nil && prior.Phase == "pending" {
		v.details = append(v.details, "A previous operation is unfinished. This new confirmed plan preserves its evidence in history and does not replay its destructive steps.")
	}
	if action == "mount.attach" || action == "mount.open" || action == "mount.settings" {
		if _, err = plannedFstab(action, v, p); err != nil {
			return nil, err
		}
	}
	raw, err := json.Marshal([]any{p, v.identities, v.selected, v.witness, storagebase.Hash(conf), v.options, revision, v.remountParent, v.stale})
	if err != nil {
		return nil, err
	}
	var state []any
	if err = systemops.Decode(raw, &state); err != nil {
		return nil, err
	}
	v.fingerprint, err = systemops.Fingerprint(action, state[0].(map[string]any), state[1:])
	return v, err
}

var checkers = map[string]string{"vfat": "fsck.fat", "exfat": "fsck.exfat", "ext2": "e2fsck", "ext3": "e2fsck", "ext4": "e2fsck"}

func (s *service) checkAvailable(fs string) bool {
	tool := checkers[fs]
	return tool != "" && s.tool(tool)
}
