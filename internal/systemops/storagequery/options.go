package storagequery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops/disksleep"
)

var filesystemFormats = []struct {
	name    string
	command []string
}{
	{"ext4", []string{"mkfs.ext4", "-F"}},
	{"xfs", []string{"mkfs.xfs", "-f"}},
	{"btrfs", []string{"mkfs.btrfs", "-f"}},
	{"vfat", []string{"mkfs.vfat"}},
	{"fat32", []string{"mkfs.vfat", "-F", "32"}},
	{"ntfs", []string{"mkfs.ntfs", "--quick"}},
}

func FormatCommand(name string) []string {
	for _, format := range filesystemFormats {
		if format.name == name {
			return append([]string(nil), format.command...)
		}
	}
	return nil
}

type optionsEnvironment struct {
	units, health string
	now           time.Time
	available     func(string) bool
	sleep         func() (map[string]any, error)
}

func defaultOptionsEnvironment() optionsEnvironment {
	return optionsEnvironment{
		units: "/etc/systemd/system", health: "/run/panasms-filesystems", now: time.Now(),
		available: func(name string) bool { _, err := exec.LookPath(name); return err == nil },
		sleep: func() (map[string]any, error) {
			var output bytes.Buffer
			if err := disksleep.Command("query", strings.NewReader(""), &output); err != nil {
				return nil, err
			}
			var result map[string]any
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				return nil, err
			}
			return result, nil
		},
	}
}

var octalEscape = regexp.MustCompile(`\\([0-7]{3})`)

func decodeMountpoint(value string) string {
	return octalEscape.ReplaceAllStringFunc(value, func(match string) string { n, _ := strconv.ParseInt(match[1:], 8, 32); return string(rune(n)) })
}

func mountSettings(row map[string]any, fstab string) any {
	uuid, _ := row["uuid"].(string)
	if uuid == "" {
		return nil
	}
	for _, line := range strings.Split(fstab, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "UUID="+uuid {
			continue
		}
		options := map[string]bool{}
		for _, option := range strings.Split(f[3], ",") {
			options[option] = true
		}
		policy := "boot"
		if options["noauto"] {
			policy = "manual"
		}
		if options["x-systemd.automount"] {
			policy = "on-demand"
		}
		return map[string]any{"point": decodeMountpoint(f[1]), "automount": !options["noauto"], "mountPolicy": policy, "readOnly": options["ro"]}
	}
	return nil
}

func reason(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func publicRow(input map[string]any) map[string]any {
	row := make(map[string]any, len(input))
	for k, v := range input {
		if k != "maj:min" {
			row[k] = v
		}
	}
	return row
}

func (s *service) options(ctx context.Context, env optionsEnvironment) (any, error) {
	p, err := s.preflight(ctx)
	if err != nil {
		return nil, err
	}
	fstab, err := os.ReadFile(s.fstab)
	if err != nil {
		return nil, err
	}
	rows := []map[string]any{}
	for _, path := range p.Inventory.Order {
		d := p.Inventory.Rows[path]
		row := publicRow(d)
		if d["type"] == "disk" {
			row["media"] = mediaInfo(d, s.sys)
			serial, _ := d["serial"].(string)
			legacy, schedules, err := smartSchedules(serial, env.units, env.now)
			if err != nil {
				return nil, err
			}
			row["smartSchedule"], row["smartSchedules"] = legacy, schedules
		}
		row["mountSettings"] = mountSettings(d, string(fstab))
		row["filesystemHealth"] = cachedHealth(path, s.sys, env.health)
		protected, layout, busy := reason(p.Protected(path, false)), reason(p.Layout(path)), reason(p.Unused(path, false))
		row["protectedReason"], row["layoutReason"], row["busyReason"] = protected, layout, busy
		raid := protected
		if raid == "" {
			raid = busy
		}
		if fs, _ := d["fstype"].(string); raid == "" && fs != "" {
			if fs == "linux_raid_member" {
				raid = "The disk holds the metadata of a former array. Wipe it in Partitions and mounts before reuse."
			} else {
				raid = "The disk contains a file system. Prepare it in Partitions and mounts."
			}
		}
		row["raidReason"] = raid
		name := d["kname"].(string)
		row["raidEligible"] = d["type"] == "disk" && raid == "" && !strings.HasPrefix(name, "zram") && !strings.HasPrefix(name, "ram")
		ejectable := d["type"] == "disk" && protected == ""
		if _, err := os.Stat(filepath.Join(s.sys, name, "device/delete")); err != nil {
			ejectable = false
		}
		if ejectable {
			for _, child := range p.Inventory.Descendants(path) {
				c := p.Inventory.Rows[child]
				holders, err := s.dependencies(c["kname"].(string), "holders")
				if err != nil || len(holders) > 0 || c["type"] != "disk" && c["type"] != "part" {
					ejectable = false
					break
				}
			}
		}
		row["ejectable"] = ejectable
		rows = append(rows, row)
	}
	result, err := env.sleep()
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("missing disk sleep status")
	}
	formats := []string{}
	capabilities := map[string]any{}
	for _, format := range filesystemFormats {
		fs := format.name
		create := env.available(format.command[0])
		if create {
			formats = append(formats, fs)
		}
		cap := map[string]any{"create": create, "grow": fs == "ext4" || fs == "btrfs" || fs == "xfs", "shrink": fs == "ext4" || fs == "btrfs"}
		if fs == "ext4" {
			cap["resizeRequiresUnmount"] = true
		}
		if fs == "xfs" || fs == "btrfs" {
			cap["resizeRequiresMount"] = true
		}
		capabilities[fs] = cap
	}
	result["devices"], result["formats"], result["capabilities"] = rows, formats, capabilities
	return result, nil
}

func Options(ctx context.Context) (any, error) {
	return defaultService().options(ctx, defaultOptionsEnvironment())
}
