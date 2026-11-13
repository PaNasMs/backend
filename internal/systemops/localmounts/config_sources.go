package localmounts

import (
	"os"
	"path/filepath"
	"strings"

	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagequery"
)

const externalConfig = "This disk has a mount entry managed outside the panel. Review it before preparing the disk."

// The panel owns only its canonical UUID rows. Other fstab spellings may still
// refer to the selected disk or a partition whose signature will be destroyed.
func (s *service) checkPrepareSources(config string, pf *storagequery.Preflight, selected map[string]storagequery.StorageIdentity) error {
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		source := folders.UnescapeMount(fields[0])
		key, value, tag := strings.Cut(source, "=")
		if len(value) >= 2 && (value[0] == '"' || value[0] == 39) && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		if strings.HasPrefix(source, "/dev/") {
			resolved, err := s.resolve(source)
			if _, ok := selected[source]; ok {
				return reject(externalConfig)
			}
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if _, ok := selected[resolved]; ok {
				return reject(externalConfig)
			}
			continue
		}
		if !tag || value == "" {
			continue
		}
		for path := range selected {
			row := pf.Inventory.Rows[path]
			switch key {
			case "UUID":
				uuid := text(row, "uuid")
				if strings.EqualFold(uuid, value) && source != "UUID="+uuid {
					return reject(externalConfig)
				}
			case "LABEL":
				if text(row, "label") == value {
					return reject(externalConfig)
				}
			case "PARTUUID":
				if strings.EqualFold(text(row, "partuuid"), value) {
					return reject(externalConfig)
				}
			case "PARTLABEL":
				if text(row, "type") != "part" {
					continue
				}
				event, err := os.ReadFile(filepath.Join(s.sys, filepath.Base(path), "uevent"))
				if err != nil {
					return reject("Could not verify storage dependencies. No changes were made.")
				}
				for _, field := range strings.Split(string(event), "\n") {
					if field == "PARTNAME="+value {
						return reject(externalConfig)
					}
				}
			}
		}
	}
	return nil
}

// CheckRemovalSources also covers fstab rows that refer to an array through
// a device alias, partition label or PARTUUID rather than the filesystem UUID.
func CheckRemovalSources(config string, pf *storagequery.Preflight, paths []string) error {
	selected := make(map[string]storagequery.StorageIdentity, len(paths))
	for _, path := range paths {
		selected[path] = storagequery.StorageIdentity{}
	}
	return defaultService().checkPrepareSources(config, pf, selected)
}
