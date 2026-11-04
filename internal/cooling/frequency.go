package cooling

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const cpuPolicies = "sys/devices/system/cpu/cpufreq"

func cpuFrequencies(root string) []int {
	model, _ := os.ReadFile(filepath.Join(root, "proc/device-tree/model"))
	if !strings.HasPrefix(string(model), "Raspberry Pi ") {
		return nil
	}
	policies, _ := filepath.Glob(filepath.Join(root, cpuPolicies, "policy[0-9]*"))
	if len(policies) != 1 || filepath.Base(policies[0]) != "policy0" {
		return nil
	}
	dir := policies[0]
	info, err := os.Stat(filepath.Join(dir, "scaling_max_freq"))
	if err != nil || info.Mode().Perm()&0200 == 0 {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, "scaling_available_frequencies"))
	if err != nil {
		return nil
	}
	read := func(name string) int {
		v, _ := os.ReadFile(filepath.Join(dir, name))
		n, _ := strconv.Atoi(strings.TrimSpace(string(v)))
		return n
	}
	min, max := read("scaling_min_freq"), read("cpuinfo_max_freq")
	var values []int
	for _, s := range strings.Fields(string(data)) {
		n, err := strconv.Atoi(s)
		if err == nil && min > 0 && n >= min && n <= max {
			values = append(values, n)
		}
	}
	slices.Sort(values)
	return slices.Compact(values)
}

func ApplyFrequency(root string, limit int) error {
	values := cpuFrequencies(root)
	if len(values) == 0 {
		return fmt.Errorf("CPU frequency control unavailable")
	}
	dir := filepath.Join(root, cpuPolicies, "policy0")
	if limit == 0 {
		raw, err := os.ReadFile(filepath.Join(dir, "cpuinfo_max_freq"))
		if err != nil {
			return err
		}
		limit, err = strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || limit <= 0 {
			return fmt.Errorf("invalid CPU maximum")
		}
	} else if !slices.Contains(values, limit) {
		return fmt.Errorf("unsupported CPU frequency")
	}
	return os.WriteFile(filepath.Join(dir, "scaling_max_freq"), []byte(strconv.Itoa(limit)), 0644)
}
