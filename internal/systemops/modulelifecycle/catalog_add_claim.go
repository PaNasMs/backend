package modulelifecycle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const claimPrefix = ".source-add-claim."
const claimTag = "panasms-source-add-v1:"

// The symlink target is reservation data. The transaction ID must agree with
// the filename before the helper can fence its signer or retire the claim.
func claimedPublisher(dir *os.File, name string) (string, error) {
	var buf [512]byte
	n, err := unix.Readlinkat(int(dir.Fd()), name, buf[:])
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EINVAL) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	payload, tagged := strings.CutPrefix(string(buf[:n]), claimTag)
	signer, id, ok := strings.Cut(payload, ":")
	if !tagged || !ok || !signerPattern.MatchString(signer) || strings.HasPrefix(signer, "panasms-") || !sourceAddID.MatchString(id) || name != claimPrefix+id {
		return "", nil
	}
	return signer, nil
}

func publisherClaims(dir *os.File) (map[string]string, error) {
	names, err := sourceRecordNames(dir, claimPrefix)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]string, len(names))
	for _, name := range names {
		signer, err := claimedPublisher(dir, name)
		if err != nil {
			return nil, err
		}
		if signer != "" {
			claims[name] = signer
		}
	}
	return claims, nil
}

func (c catalogService) claimPublisher(dir *os.File, change *sourceChange) error {
	var name string
	for {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		change.AddID = hex.EncodeToString(nonce[:])
		name = claimPrefix + change.AddID
		err := unix.Symlinkat(claimTag+change.AddSigner+":"+change.AddID, int(dir.Fd()), name)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	if c.sourceBoundary != nil {
		if err := c.sourceBoundary("enrollment-reserved"); err != nil {
			return err
		}
	}
	return c.finishPublisherClaim(dir, name, change.AddSigner)
}

func (c catalogService) finishPublisherClaim(dir *os.File, name, signer string) error {
	if err := c.holdFailedAdd(dir, signer); err != nil {
		return err
	}
	live, err := claimedPublisher(dir, name)
	if err != nil {
		return err
	}
	if live != signer {
		return reject("Repository enrollment reservation changed")
	}
	return unlinkCatalogFile(dir, name)
}

func (c catalogService) recoverPublisherClaim(ctx context.Context, dir *os.File, r *systemops.Reporter) error {
	claims, err := publisherClaims(dir)
	if err != nil || len(claims) == 0 {
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
	for name, signer := range claims {
		if err := c.finishPublisherClaim(dir, name, signer); err != nil {
			return err
		}
	}
	return nil
}
