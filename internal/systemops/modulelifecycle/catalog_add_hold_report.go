package modulelifecycle

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// A signer can remain held after its repository was removed. Read the durable
// holds directly and identify foreign entries that would prevent a fresh add.
func (c catalogService) inactivePublisherHolds(dir *os.File) (map[string][]string, error) {
	names, err := stateDirectoryNames(dir)
	if err != nil {
		return nil, err
	}
	inactive := map[string][]string{}
	for _, name := range names {
		suffix, matched := strings.CutPrefix(name, publisherHoldPrefix)
		signer, id, valid := strings.Cut(suffix, ".")
		if !matched || !valid || !signerPattern.MatchString(signer) || !sourceAddID.MatchString(id) {
			continue
		}
		state, err := c.publisherHoldAt(dir, name, 0)
		if err == nil && state == publisherHeld {
			// A recognizable hold can still be immutable or on a read-only mount.
			_, err = c.publisherHoldAt(dir, name, publisherCheckWrite)
		}
		if foreignPublisherHold(err) {
			inactive[signer] = append(inactive[signer], filepath.Join(c.root, name))
			continue
		}
		if err != nil {
			return nil, err
		}
		if state == publisherHeld && len(inactive[signer]) == 0 {
			inactive[signer] = nil
		}
	}
	for _, paths := range inactive {
		slices.Sort(paths)
	}
	return inactive, nil
}
