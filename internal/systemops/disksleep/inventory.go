package disksleep

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type device struct {
	Name       string   `json:"kname"`
	Path       string   `json:"path"`
	Kind       string   `json:"type"`
	Transport  string   `json:"tran"`
	Serial     string   `json:"serial"`
	Rotational bool     `json:"rota"`
	ReadOnly   bool     `json:"ro"`
	FSType     string   `json:"fstype"`
	UUID       string   `json:"uuid"`
	PartUUID   string   `json:"partuuid"`
	Label      string   `json:"label"`
	PartType   string   `json:"parttype"`
	Mounts     []string `json:"mountpoints"`
	Children   []device `json:"children"`
}

type disk struct{ Path, Name, Key string }

func systemPath(p string) bool {
	if p == "[SWAP]" {
		return true
	}
	for _, root := range []string{"/", "/boot", "/efi", "/usr", "/var", "/home", "/etc", "/opt"} {
		if p == root || root != "/" && strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}
func protected(d device, sources map[string]bool) bool {
	for _, m := range d.Mounts {
		if systemPath(m) {
			return true
		}
	}
	if d.ReadOnly || d.FSType == "swap" {
		return true
	}
	switch strings.ToLower(d.PartType) {
	case "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "21686148-6449-6e6f-744e-656564454649", "bc13c2ff-59e6-4262-a352-b275fd6f7172", "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "0xef", "0x82":
		return true
	}
	for _, key := range []string{d.Path, "UUID=" + d.UUID, "PARTUUID=" + d.PartUUID, "LABEL=" + d.Label} {
		if sources[key] {
			return true
		}
	}
	for _, child := range d.Children {
		if protected(child, sources) {
			return true
		}
	}
	return false
}
func (s *service) inventory() ([]disk, error) {
	data, _, err := s.run("lsblk", "--json", "--tree", "--paths", "--output", "KNAME,PATH,TYPE,TRAN,SERIAL,ROTA,RO,FSTYPE,UUID,PARTUUID,LABEL,PARTTYPE,MOUNTPOINTS")
	if err != nil {
		return nil, err
	}
	var inv struct {
		Devices []device `json:"blockdevices"`
	}
	if err = json.Unmarshal(data, &inv); err != nil {
		return nil, err
	}
	fstab, err := os.ReadFile(s.fstab)
	if err != nil {
		return nil, err
	}
	sources := map[string]bool{}
	for _, line := range strings.Split(string(fstab), "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(f) >= 3 && (systemPath(f[1]) || f[2] == "swap") {
			sources[f[0]] = true
		}
	}
	var disks []disk
	seen := map[string]bool{}
	var visit func(device) error
	visit = func(d device) error {
		d.Name = filepath.Base(d.Name)
		if d.Kind == "disk" && d.Transport == "sata" && d.Rotational && d.Serial != "" && !protected(d, sources) && !seen[d.Path] {
			seq, err := os.ReadFile(filepath.Join(s.sys, d.Name, "diskseq"))
			if err != nil {
				return err
			}
			if strings.TrimSpace(string(seq)) == "" {
				return fmt.Errorf("missing disk identity for %s", d.Path)
			}
			disks = append(disks, disk{d.Path, d.Name, d.Serial + ":" + strings.TrimSpace(string(seq))})
			seen[d.Path] = true
		}
		for _, child := range d.Children {
			if err := visit(child); err != nil {
				return err
			}
		}
		return nil
	}
	for _, d := range inv.Devices {
		if err := visit(d); err != nil {
			return nil, err
		}
	}
	return disks, nil
}

func (s *service) busy(name string, seen map[string]bool) (bool, error) {
	if seen[name] {
		return false, nil
	}
	seen[name] = true
	node := filepath.Join(s.sys, name)
	v, err := os.ReadFile(filepath.Join(node, "md/sync_action"))
	if err == nil && strings.TrimSpace(string(v)) != "idle" {
		return true, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	holders, err := os.ReadDir(filepath.Join(node, "holders"))
	if err != nil {
		return false, err
	}
	children, err := os.ReadDir(node)
	if err != nil {
		return false, err
	}
	names := []string{}
	for _, h := range holders {
		names = append(names, h.Name())
	}
	for _, c := range children {
		if _, err := os.Stat(filepath.Join(node, c.Name(), "partition")); err == nil {
			names = append(names, c.Name())
		}
	}
	for _, n := range names {
		b, err := s.busy(n, seen)
		if b || err != nil {
			return b, err
		}
	}
	return false, nil
}
