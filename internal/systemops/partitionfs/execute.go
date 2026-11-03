package partitionfs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

func Execute(ctx context.Context, action string, params map[string]any, expected string, r *systemops.Reporter) (json.RawMessage, error) {
	domain, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer domain.Close()
	initial, err := storagequery.LoadPreflight(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	target, err := filepath.EvalSymlinks(text(params, "target"))
	if err != nil || initial.Inventory.Rows[target] == nil {
		return nil, systemops.BeforeMutation(reject("The device no longer exists"))
	}
	identity, err := initial.Identity(target)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	locks := []*os.File{}
	defer func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Close()
		}
	}()
	lockPaths := map[string]bool{}
	for _, device := range identity.Devices {
		lockPaths[device.Path] = true
	}
	scope := target
	if strings.HasPrefix(action, "partition.") && action != "partition.create" {
		scope, err = oneParent(target, initial)
		if err != nil {
			return nil, systemops.BeforeMutation(err)
		}
	}
	for _, child := range initial.Inventory.Descendants(scope) {
		lockPaths[child] = true
	}
	ordered := make([]string, 0, len(lockPaths))
	for path := range lockPaths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	for _, path := range ordered {
		lock, err := storagebase.DeviceLock(ctx, path)
		if err != nil {
			return nil, systemops.BeforeMutation(err)
		}
		locks = append(locks, lock)
	}
	current, err := storagequery.LoadPreflight(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	s := defaultService()
	plan, err := s.prepareTarget(ctx, action, params, current, target)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if expected == "" || plan.fingerprint != expected || !reflect.DeepEqual(identity, plan.identity) {
		return nil, systemops.BeforeMutation(reject("State has changed. Review a new operation plan."))
	}
	if err = storagebase.CheckPendingRoots("partitionfs", target, plan.identity); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	pins, err := pinPlan(action, plan)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer func() {
		for _, pin := range pins {
			pin.Close()
		}
	}()
	s.run = pinnedRunner(s.run, pins)
	return s.executePrepared(ctx, action, params, plan, r)
}
func (s *service) executePrepared(ctx context.Context, action string, params map[string]any, plan *prepared, r *systemops.Reporter) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if plan.previous != nil && !plan.previous.Complete && plan.previous.FstabDesired != "" && plan.config != plan.previous.FstabDesired {
		return nil, systemops.BeforeMutation(reject("Storage configuration recovery is required before another operation"))
	}
	desired := plan.config
	uuid := text(plan.row, "uuid")
	if uuid != "" && (action == "partition.delete" || action == "filesystem.format" || action == "filesystem.remove") {
		var err error
		desired, err = storagebase.EditFstab(plan.config, map[string]bool{uuid: true}, "", nil)
		if err != nil {
			return nil, systemops.BeforeMutation(err)
		}
	}
	if err := s.archive(plan.previous); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	state := &transaction{Schema: 1, Domain: "partitionfs", Phase: "pending", Action: action, Target: plan.target, Fingerprint: plan.fingerprint, Identity: plan.identity, FstabBefore: storagebase.Hash(plan.config), FstabDesired: desired, Steps: []step{}}
	if err := s.save(state); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	run := func(stepName string, args []string, input string, accepted ...int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.revalidate(ctx, action, state); err != nil {
			return err
		}
		state.Steps = append(state.Steps, step{Name: stepName})
		if err := s.save(state); err != nil {
			return err
		}
		_, err := s.run(ctx, args, systemops.CommandOptions{Input: []byte(input), Accepted: accepted, Operation: true, Reporter: r, Timeout: 24 * time.Hour})
		if err != nil {
			return err
		}
		state.Steps[len(state.Steps)-1].Completed = true
		return s.save(state)
	}
	target := plan.target
	fs := text(plan.row, "fstype")
	kernel := func(args []string, verify func() error) error {
		// Once the on-disk table changes, finish kernel synchronization even when
		// cancellation arrives; no subsequent destructive step is retried.
		_, err := s.run(context.WithoutCancel(ctx), args, systemops.CommandOptions{Accepted: []int{0, 1}, Operation: true, Reporter: r})
		if err != nil {
			return err
		}
		_, err = s.run(context.WithoutCancel(ctx), []string{"udevadm", "settle"}, systemops.CommandOptions{Operation: true, Reporter: r})
		if err != nil {
			return err
		}
		return verify()
	}
	var err error
	switch action {
	case "partition.create":
		table := plan.table
		if table == nil {
			if err = run("create-partition-table", []string{"parted", "--script", target, "mklabel", "gpt"}, ""); err != nil {
				return nil, err
			}
			table, err = s.table(context.WithoutCancel(ctx), target)
			if err != nil {
				return nil, err
			}
		}
		before, err := tableParts(table)
		if err != nil {
			return nil, err
		}
		sector, err := sectorSize(table)
		if err != nil {
			return nil, err
		}
		input := fmt.Sprintf("start=%d, size=%d, type=L\n", plan.start*mib/sector, (plan.end-plan.start)*mib/sector)
		if err = run("append-partition", []string{"sfdisk", "--no-reread", "--no-tell-kernel", "--wipe", "never", "--wipe-partitions", "never", "--append", target}, input); err != nil {
			return nil, err
		}
		after, err := s.table(context.WithoutCancel(ctx), target)
		if err != nil {
			return nil, err
		}
		parts, err := tableParts(after)
		if err != nil {
			return nil, err
		}
		contains := func(list []map[string]any, part map[string]any) bool {
			for _, other := range list {
				if reflect.DeepEqual(other, part) {
					return true
				}
			}
			return false
		}
		for _, part := range before {
			if !contains(parts, part) {
				return nil, reject("Could not confirm the new partition")
			}
		}
		added := []map[string]any{}
		for _, part := range parts {
			if !contains(before, part) {
				added = append(added, part)
			}
		}
		if len(added) != 1 {
			return nil, reject("Could not confirm the new partition")
		}
		num := regexp.MustCompile(`[0-9]+$`).FindString(text(added[0], "node"))
		if num == "" {
			return nil, reject("Could not confirm the new partition")
		}
		err = kernel([]string{"partx", "--add", "--nr", num, target}, func() error { return s.verifyKernel(added[0], sector) })
	case "partition.delete":
		n, e := number(plan.row["partn"])
		if e != nil {
			return nil, e
		}
		num := strconv.FormatUint(n, 10)
		if err = run("delete-partition", []string{"sfdisk", "--no-reread", "--no-tell-kernel", "--delete", plan.parent, num}, ""); err != nil {
			return nil, err
		}
		if err = s.verifyLayoutChange(context.WithoutCancel(ctx), plan, true); err != nil {
			return nil, err
		}
		err = kernel([]string{"partx", "--delete", "--nr", num, plan.parent}, func() error {
			_, e := os.Lstat(filepath.Join(s.sys, text(plan.row, "kname")))
			if !os.IsNotExist(e) {
				return reject("The partition table changed, but the kernel has not confirmed it. Restart the NAS before retrying.")
			}
			return nil
		})
	case "partition.resize":
		capacity, e := number(plan.row["size"])
		if e != nil {
			return nil, e
		}
		shrink := plan.size*mib < capacity
		if fs != "" {
			if err = run("check-filesystem", []string{"e2fsck", "-f", "-p", target}, "", 0, 1); err != nil {
				return nil, err
			}
		}
		if fs != "" && shrink {
			if err = run("shrink-filesystem", []string{"resize2fs", target, fmt.Sprintf("%dM", plan.size-4)}, ""); err != nil {
				return nil, err
			}
		}
		sector, e := sectorSize(plan.table)
		if e != nil {
			return nil, e
		}
		n, e := number(plan.row["partn"])
		if e != nil {
			return nil, e
		}
		num := strconv.FormatUint(n, 10)
		if err = run("resize-partition", []string{"sfdisk", "--no-reread", "--no-tell-kernel", "-N", num, plan.parent}, fmt.Sprintf("size=%d\n", plan.size*mib/sector)); err != nil {
			return nil, err
		}
		if err = s.verifyLayoutChange(context.WithoutCancel(ctx), plan, false); err != nil {
			return nil, err
		}
		err = kernel([]string{"partx", "--update", "--nr", num, plan.parent}, func() error {
			return s.verifyKernel(map[string]any{"node": target, "start": plan.start / sector, "size": plan.size * mib / sector}, sector)
		})
		if err == nil && fs != "" {
			err = run("grow-filesystem", []string{"resize2fs", target}, "")
		}
	case "filesystem.remove":
		err = run("remove-filesystem", []string{"wipefs", "--all", "--types", fs, "--", target}, "")
	case "filesystem.format":
		format := text(params, "format")
		args := map[string][]string{"ext4": {"mkfs.ext4", "-F"}, "xfs": {"mkfs.xfs", "-f"}, "btrfs": {"mkfs.btrfs", "-f"}, "vfat": {"mkfs.vfat"}}[format]
		if len(args) == 0 {
			return nil, reject("The utility for creating this file system is unavailable")
		}
		err = run("format-filesystem", append(args, target), "")
	case "filesystem.resize":
		if strings.HasPrefix(fs, "ext") {
			if err = run("check-filesystem", []string{"e2fsck", "-f", "-p", target}, "", 0, 1); err == nil {
				err = run("resize-filesystem", []string{"resize2fs", target, fmt.Sprintf("%dM", plan.size)}, "")
			}
		} else {
			points := mounted(plan.row)
			if len(points) == 0 {
				return nil, reject("The file system must be mounted")
			}
			dir, e := folders.OpenDirectory(points[0])
			if e != nil {
				return nil, e
			}
			defer dir.Close()
			rows, e := folders.ReadMounts()
			if e != nil {
				return nil, e
			}
			mount, e := folders.DirectoryMount(dir, rows)
			if e != nil {
				return nil, e
			}
			found := false
			for _, id := range plan.identity.Devices {
				if id.Path == target && id.DeviceNumber == mount.Device {
					found = true
				}
			}
			if !found || mount.FSType != fs || mount.Target != points[0] {
				return nil, reject("The mount changed; review a new operation plan")
			}
			pinned := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), dir.Fd())
			args := []string{"xfs_growfs", pinned}
			if fs == "btrfs" {
				size := "max"
				if plan.size != 0 {
					size = fmt.Sprintf("%dM", plan.size)
				}
				args = []string{"btrfs", "filesystem", "resize", size, pinned}
			}
			err = run("resize-filesystem", args, "")
		}
	default:
		return nil, reject("Unknown storage operation")
	}
	if err != nil {
		return nil, err
	}
	if action == "filesystem.format" || action == "filesystem.remove" {
		_, err = s.run(context.WithoutCancel(ctx), []string{"udevadm", "trigger", "--action=change", "--settle", target}, systemops.CommandOptions{Accepted: []int{0, 1}, Operation: true, Reporter: r})
		if err != nil {
			return nil, err
		}
	}
	if desired != plan.config {
		state.Steps = append(state.Steps, step{Name: "update-fstab"})
		if err = s.save(state); err != nil {
			return nil, err
		}
		if err = s.writeConfig(context.WithoutCancel(ctx), state.FstabBefore, desired, r); err != nil {
			return nil, err
		}
		state.Steps[len(state.Steps)-1].Completed = true
	}
	state.Complete = true
	state.Phase = "complete"
	if err = s.save(state); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"ok": true})
}

func revalidate(ctx context.Context, action string, state *transaction) error {
	p, err := storagequery.LoadPreflight(ctx)
	if err != nil {
		return err
	}
	if err = p.Protected(state.Target, action == "partition.create"); err != nil {
		return err
	}
	if action == "partition.create" {
		if err = p.Layout(state.Target); err != nil {
			return err
		}
	} else if action != "filesystem.resize" || strings.HasPrefix(text(p.Inventory.Rows[state.Target], "fstype"), "ext") {
		if err = p.Unused(state.Target, false); err != nil {
			return err
		}
	}

	now, err := p.Identity(state.Target)
	if err != nil {
		return err
	}
	if !hardwareEqual(state.Identity, now) {
		return reject("Storage identity changed; preserve the operation record and inspect the device")
	}
	return nil
}

func (s *service) verifyLayoutChange(ctx context.Context, plan *prepared, removed bool) error {
	after, err := s.table(ctx, plan.parent)
	if err != nil {
		return err
	}
	beforeParts, err := tableParts(plan.table)
	if err != nil {
		return err
	}
	afterParts, err := tableParts(after)
	if err != nil {
		return err
	}
	sector, err := sectorSize(plan.table)
	if err != nil {
		return err
	}
	newSector, err := sectorSize(after)
	if err != nil || newSector != sector || text(after, "label") != text(plan.table, "label") {
		return reject("Could not confirm the updated partition table; inspect it before retrying")
	}
	expected := map[string]map[string]any{}
	for _, part := range beforeParts {
		node := text(part, "node")
		if node == plan.target && removed {
			continue
		}
		copy := map[string]any{}
		for k, v := range part {
			copy[k] = v
		}
		if node == plan.target {
			copy["size"] = json.Number(strconv.FormatUint(plan.size*mib/sector, 10))
		}
		expected[node] = copy
	}
	if len(expected) != len(afterParts) {
		return reject("Could not confirm the updated partition table; inspect it before retrying")
	}
	for _, part := range afterParts {
		if !reflect.DeepEqual(expected[text(part, "node")], part) {
			return reject("Could not confirm the updated partition table; inspect it before retrying")
		}
		delete(expected, text(part, "node"))
	}
	if len(expected) != 0 {
		return reject("Could not confirm the updated partition table; inspect it before retrying")
	}
	return nil
}
