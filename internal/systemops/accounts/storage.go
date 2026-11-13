package accounts

import (
	"context"
	"panasms.local/backend/internal/systemops"
	"slices"
)

type StorageShare struct {
	Name     string
	Path     string
	SMB, NFS bool
}

func StorageShares() ([]StorageShare, error) { return defaultSharing().storageShares() }
func LockStorageShares(ctx context.Context) ([]StorageShare, func(), error) {
	s := defaultSharing()
	release, err := s.lockedContext(ctx, false)
	if err != nil {
		return nil, nil, err
	}
	rows, err := s.storageShares()
	if err != nil {
		release()
		return nil, nil, err
	}
	return rows, release, nil
}
func (s *sharingService) storageShares() ([]StorageShare, error) {
	for _, path := range []string{s.journal, s.restoreGuard} {
		present, err := sharingExists(path)
		if err != nil {
			return nil, err
		}
		if present {
			return nil, reject(sharingPending)
		}
	}
	snap, err := s.fileSnapshot(s.state)
	if err != nil {
		return nil, err
	}
	state := sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}}
	if snap.Exists {
		if err = systemops.Decode(snap.Data, &state); err != nil {
			return nil, err
		}
		if err = validateSharingState(state); err != nil {
			return nil, err
		}
	}
	rows := []StorageShare{}
	for _, share := range state.Shares {
		if share.SMB || share.NFS {
			rows = append(rows, StorageShare{share.Name, share.Path, share.SMB, share.NFS})
		}
	}
	return rows, nil
}

// Hold sharing configuration stable through unmount. A renamed or relocated
// share must never be removed on the authority of an old storage preview.
func LockRAIDShares(ctx context.Context, expected []StorageShare, remove []StorageShare) (func(), error) {
	s := defaultSharing()
	unlock, err := s.lockedContext(ctx, false)
	if err != nil {
		return nil, err
	}
	current, err := s.storageShares()
	if err == nil && !slices.Equal(current, expected) {
		err = reject("Shared folders changed. Review a new operation plan.")
	}
	if err == nil && len(remove) > 0 {
		names := make([]string, 0, len(remove))
		for _, share := range remove {
			if !slices.Contains(current, share) {
				unlock()
				return nil, reject("Shared folder changed")
			}
			names = append(names, share.Name)
		}
		_, err = s.removeSharesLocked(ctx, names)
	}
	if err != nil {
		unlock()
		return nil, err
	}
	return unlock, nil
}

func CheckStorageShareRemoval() error {
	s := defaultSharing()
	state, err := s.read()
	if err != nil {
		return err
	}
	changed, err := s.drift(state)
	if err != nil {
		return err
	}
	if changed {
		return reject(sharingDrift)
	}
	return nil
}
