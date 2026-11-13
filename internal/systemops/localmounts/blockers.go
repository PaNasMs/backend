package localmounts

import (
	"context"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/accounts"
	"panasms.local/backend/internal/systemops/folders"
	"panasms.local/backend/internal/systemops/storagebase"

	"slices"

	"strings"
)

func defaultBlockers(ctx context.Context, selected, all []folders.LiveMount) error {
	if len(selected) == 0 {
		return nil
	}
	shares, err := accounts.StorageShares()
	if err != nil {
		return err
	}
	return CheckStorageBlockers(ctx, selected, all, shares, nil, nil)
}

// ignoreExports contains managed exports scheduled for removal before unmount.
// The caller repeats this check without exclusions once sharing has been updated.
func CheckStorageBlockers(ctx context.Context, selected, all []folders.LiveMount, shares []accounts.StorageShare, ignoreExports, closingSMB map[string]bool) error {
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
	active, err := storagebase.ActiveNFSExports()
	if err != nil {
		return err
	}
	active = slices.DeleteFunc(active, func(path string) bool { return ignoreExports[path] })
	return storagebase.CheckRAIDRemovalBlockers(ctx, selected, all, homes, paths, active, closingSMB)
}
