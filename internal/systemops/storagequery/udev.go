package storagequery

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var deviceNumberPattern = regexp.MustCompile(`^[0-9]+:[0-9]+$`)

// A null filesystem field is only meaningful after udev has initialized the
// device. Never replace an unavailable cache with a privileged signature probe.
func requireMetadataCache(rows []map[string]any, root string) error {
	for _, row := range rows {
		number, _ := row["maj:min"].(string)
		if !deviceNumberPattern.MatchString(number) {
			return rejectf("Could not verify storage dependencies. No changes were made.")
		}
		data, err := os.ReadFile(filepath.Join(root, "b"+number))
		if err != nil {
			return rejectf("Could not verify storage dependencies. No changes were made.")
		}
		initialized := false
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(line, "I:"); ok {
				stamp, err := strconv.ParseUint(value, 10, 64)
				initialized = err == nil && stamp > 0
			}
		}
		if !initialized {
			return rejectf("Could not verify storage dependencies. No changes were made.")
		}
		if children, ok := row["children"].([]any); ok {
			nested := make([]map[string]any, 0, len(children))
			for _, child := range children {
				value, ok := child.(map[string]any)
				if !ok {
					return rejectf("Could not verify storage dependencies. No changes were made.")
				}
				nested = append(nested, value)
			}
			if err := requireMetadataCache(nested, root); err != nil {
				return err
			}
		}
	}
	return nil
}
