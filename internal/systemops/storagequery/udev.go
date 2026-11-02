package storagequery

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var deviceNumberPattern = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
var udevHexEscape = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)

func readMetadataSnapshot(root string) (map[string][]byte, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	result := map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "b") || !deviceNumberPattern.MatchString(name[1:]) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return nil, err
		}
		result[name[1:]] = data
	}
	return result, nil
}

func observedBlockInventory(ctx context.Context, root string, read func(context.Context) ([]map[string]any, error)) ([]map[string]any, error) {
	before, err := readMetadataSnapshot(root)
	if err != nil {
		return nil, rejectf("Could not verify storage dependencies. No changes were made.")
	}
	rows, err := read(ctx)
	if err != nil {
		return nil, err
	}
	after, err := readMetadataSnapshot(root)
	if err != nil {
		return nil, rejectf("Could not verify storage dependencies. No changes were made.")
	}
	if err := requireMetadataCache(rows, before, after); err != nil {
		return nil, err
	}
	return rows, nil
}

func unescapeUdev(value string) string {
	return udevHexEscape.ReplaceAllStringFunc(value, func(match string) string { n, _ := strconv.ParseUint(match[2:], 16, 8); return string([]byte{byte(n)}) })
}

// Null properties mean a blank device only when the initialized cache stayed
// unchanged and lsblk agrees with its protection-relevant properties. Root can
// read cache files that the unprivileged inventory subprocess cannot read.
func requireMetadataCache(rows []map[string]any, before, after map[string][]byte) error {
	failed := func() error { return rejectf("Could not verify storage dependencies. No changes were made.") }
	for _, row := range rows {
		number, _ := row["maj:min"].(string)
		if !deviceNumberPattern.MatchString(number) {
			return failed()
		}
		previous, existed := before[number]
		data, exists := after[number]
		if !existed || !exists || !bytes.Equal(previous, data) {
			return failed()
		}
		initialized := false
		properties := map[string]string{}
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(line, "I:"); ok {
				stamp, err := strconv.ParseUint(value, 10, 64)
				initialized = err == nil && stamp > 0
			}
			if value, ok := strings.CutPrefix(line, "E:"); ok {
				if key, val, ok := strings.Cut(value, "="); ok {
					properties[key] = val
				}
			}
		}
		if !initialized || properties["ID_FS_AMBIVALENT"] == "1" || properties["ID_PROCESSING"] == "1" {
			return failed()
		}
		for field, keys := range map[string][]string{
			"fstype": {"ID_FS_TYPE"}, "uuid": {"ID_FS_UUID_ENC", "ID_FS_UUID"}, "label": {"ID_FS_LABEL_ENC", "ID_FS_LABEL"},
			"partuuid": {"ID_PART_ENTRY_UUID"}, "parttype": {"ID_PART_ENTRY_TYPE"},
		} {
			expected := ""
			for _, key := range keys {
				if value, ok := properties[key]; ok {
					expected = value
					if strings.HasSuffix(key, "_ENC") {
						expected = unescapeUdev(expected)
					}
					break
				}
			}
			actual, ok := row[field].(string)
			if !ok && row[field] != nil {
				return failed()
			}
			if actual != expected {
				return failed()
			}
		}
		if children, ok := row["children"].([]any); ok {
			nested := make([]map[string]any, 0, len(children))
			for _, child := range children {
				value, ok := child.(map[string]any)
				if !ok {
					return failed()
				}
				nested = append(nested, value)
			}
			if err := requireMetadataCache(nested, before, after); err != nil {
				return err
			}
		}
	}
	return nil
}
