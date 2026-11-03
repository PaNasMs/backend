package accounts

import (
	"context"
	"panasms.local/backend/internal/systemops"
)

type StorageShare struct {
	Name string
	Path string
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
			rows = append(rows, StorageShare{share.Name, share.Path})
		}
	}
	return rows, nil
}
