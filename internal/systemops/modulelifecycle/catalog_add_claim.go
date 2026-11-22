package modulelifecycle

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const sourceAddClaim = ".source-add-claim"

// A symlink records the complete reservation in a single namespace operation.
// Only its contents are read. It is never used as a filesystem path.
func claimedPublisher(dir *os.File) (signer, claim string, err error) {
	var buf [512]byte
	n, err := unix.Readlinkat(int(dir.Fd()), sourceAddClaim, buf[:])
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	claim = string(buf[:n])
	parts := strings.Split(claim, ":")
	if len(parts) != 3 || parts[0] != "panasms-source-add-v1" || !signerPattern.MatchString(parts[1]) || strings.HasPrefix(parts[1], "panasms-") || !sourceAddID.MatchString(parts[2]) {
		return "", "", nil
	}
	return parts[1], claim, nil
}

func (c catalogService) claimPublisher(dir *os.File, change sourceChange) error {
	claim := "panasms-source-add-v1:" + change.AddSigner + ":" + change.AddID
	if err := unix.Symlinkat(claim, int(dir.Fd()), sourceAddClaim); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	if c.sourceBoundary != nil {
		if err := c.sourceBoundary("enrollment-reserved"); err != nil {
			return err
		}
	}
	return c.finishPublisherClaim(dir, change.AddSigner, claim)
}

func (c catalogService) finishPublisherClaim(dir *os.File, signer, claim string) error {
	if err := c.holdFailedAdd(dir, signer); err != nil {
		return err
	}
	_, live, err := claimedPublisher(dir)
	if err != nil {
		return err
	}
	if live != claim {
		return reject("Repository enrollment reservation changed")
	}
	return unlinkCatalogFile(dir, sourceAddClaim)
}

func (c catalogService) recoverPublisherClaim(ctx context.Context, dir *os.File, r *systemops.Reporter) error {
	signer, claim, err := claimedPublisher(dir)
	if err != nil || signer == "" {
		return err
	}
	lock, err := c.store.lock(ctx, r)
	if err != nil {
		return err
	}
	defer lock.Close()
	if repaired, _ := ctx.Value(sourceRepairKey{}).(*bool); repaired != nil {
		*repaired = true
	}
	return c.finishPublisherClaim(dir, signer, claim)
}
