package localmounts

import (
	"context"
	"os"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"
	"regexp"
	"strconv"
	"strings"
)

var exportEscape = regexp.MustCompile(`\\([0-7]{3})`)

func parseExports(raw []byte) []string {
	paths := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		paths = append(paths, exportEscape.ReplaceAllStringFunc(fields[0], func(s string) string { n, _ := strconv.ParseUint(s[1:], 8, 8); return string(rune(n)) }))
	}
	return paths
}
func defaultBlockers(ctx context.Context, selected, all []folders.LiveMount) error {
	if len(selected) == 0 {
		return nil
	}
	shares, err := accounts.StorageShares()
	if err != nil {
		return err
	}
	paths := make([]storagebase.StoragePath, 0, len(shares))
	for _, share := range shares {
		paths = append(paths, storagebase.StoragePath{Name: share.Name, Path: share.Path})
	}
	raw, err := systemops.Command(ctx, []string{"getent", "passwd"}, systemops.CommandOptions{})
	if err != nil {
		return err
	}
	homes := []storagebase.StoragePath{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return reject("Could not inspect user home folders")
		}
		if strings.HasPrefix(fields[5], "/") {
			homes = append(homes, storagebase.StoragePath{Name: fields[0], Path: fields[5]})
		}
	}
	exports, err := os.ReadFile("/var/lib/nfs/etab")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return storagebase.CheckBlockers(ctx, selected, all, homes, paths, parseExports(exports))
}
