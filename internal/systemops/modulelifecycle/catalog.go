package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const maxCatalog = 2 << 20

var archiveDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var officialProject = regexp.MustCompile(`^[a-z][a-z0-9-]*/releases/download$`)

type catalogService struct {
	lifecycle
	config         string
	download       func(context.Context, string, int64) ([]byte, error)
	sourceBoundary func(string) error
}

type source struct {
	ID          string   `json:"id"`
	URL         string   `json:"url"`
	Signers     []string `json:"signers"`
	Fingerprint string   `json:"fingerprint"`
	Official    bool     `json:"official"`
}

type generation struct {
	URL           string
	Raw, Envelope []byte
}

type signedBy struct{ Algorithm, Signer, Signature string }

func catalogSigner(raw []byte) (signedBy, error) {
	var sig signedBy
	if systemops.Decode(raw, &sig) != nil || sig.Algorithm != "Ed25519" || !signerPattern.MatchString(sig.Signer) {
		return sig, reject("Invalid module catalog signature")
	}
	return sig, nil
}

func verifyCatalog(gen generation, src source, key func(string) (ed25519.PublicKey, error)) error {
	sig, err := catalogSigner(gen.Envelope)
	if err != nil {
		return err
	}
	if !slices.Contains(src.Signers, sig.Signer) {
		return reject("Untrusted module catalog signer")
	}
	public, err := key(sig.Signer)
	if err != nil {
		return err
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(sig.Signature)
	if err != nil || !ed25519.Verify(public, gen.Raw, raw) {
		return reject("Invalid module catalog signature")
	}
	return nil
}

type release struct {
	manifest      Manifest
	raw           map[string]any
	url, checksum string
	size          int64
}

type catalogIndex struct {
	order   []string
	modules map[string][]release
}

func parseCatalog(raw []byte, src source) (catalogIndex, error) {
	result := catalogIndex{modules: map[string][]release{}}
	var data struct {
		SchemaVersion int    `json:"schemaVersion"`
		ID            string `json:"id"`
		Modules       []struct {
			ID       string
			Releases []map[string]any
		}
	}
	if systemops.Decode(raw, &data) != nil || data.SchemaVersion != 1 || data.ID != src.ID || data.Modules == nil {
		return result, reject("Unsupported module catalog format")
	}
	for _, item := range data.Modules {
		if err := identifier(item.ID); err != nil {
			return result, err
		}
		if _, found := result.modules[item.ID]; found {
			return result, reject("Duplicate module in catalog")
		}
		result.order = append(result.order, item.ID)
		entries := []release{}
		if item.Releases == nil {
			return result, reject("Unsupported module catalog format")
		}
		for _, entry := range item.Releases {
			m, ok := entry["manifest"].(map[string]any)
			if !ok || text(m, "id") != item.ID {
				return result, reject("Module catalog identity mismatch")
			}
			version := text(m, "version")
			if _, err := parseVersion(version); err != nil {
				return result, err
			}
			if !slices.Contains(src.Signers, text(m, "signer")) {
				return result, reject("Module publisher differs from repository publisher")
			}
			url := text(entry, "url")
			if _, err := repositoryURL(url, false); err != nil {
				return result, err
			}
			if src.Official {
				suffix := fmt.Sprintf("/%s-v%s/%s-%s-%s.panasms", item.ID, version, item.ID, version, text(m, "architecture"))
				path, hostOK := strings.CutPrefix(url, "https://github.com/PaNasMs/")
				project, suffixOK := strings.CutSuffix(path, suffix)
				if !hostOK || !suffixOK || !officialProject.MatchString(project) {
					return result, reject("Untrusted module download URL")
				}
			}
			number, ok := entry["size"].(json.Number)
			size, err := number.Int64()
			sum, channel := text(entry, "sha256"), text(entry, "channel")
			if !ok || err != nil || size <= 0 || size > maxArchive || !archiveDigest.MatchString(sum) || channel == "" {
				return result, reject("Invalid module download metadata")
			}
			if channel == "stable" {
				entry["repository"] = src.ID
				entries = append(entries, release{Manifest(m), entry, url, sum, size})
			}
		}
		sort.SliceStable(entries, func(i, j int) bool {
			n, _ := compareVersions(text(entries[i].manifest, "version"), text(entries[j].manifest, "version"))
			return n > 0
		})
		result.modules[item.ID] = entries
	}
	return result, nil
}

func (c catalogService) readGeneration(gen generation, src source) (catalogIndex, error) {
	if gen.URL != src.URL || len(gen.Raw) > maxCatalog || len(gen.Envelope) > 4096 {
		return catalogIndex{}, reject("Invalid cached module catalog")
	}
	err := verifyCatalog(gen, src, func(signer string) (ed25519.PublicKey, error) {
		key, err := readPublicKey(c.keys, signer, c.owner)
		if err == nil && src.Fingerprint != "" && publicFingerprint(key) != src.Fingerprint {
			return nil, reject("Repository signing key changed")
		}
		return key, err
	})
	if err != nil {
		return catalogIndex{}, err
	}
	return parseCatalog(gen.Raw, src)
}

func (c catalogService) fetch(ctx context.Context, url string) (generation, error) {
	gen := generation{URL: url}
	var err error
	gen.Raw, err = c.download(ctx, url+"catalog.json", maxCatalog)
	if err == nil {
		gen.Envelope, err = c.download(ctx, url+"catalog.sig", 4096)
	}
	return gen, err
}

// Refresh each configured source independently; the raw signed bytes and
// signature are replaced together. A fallback is authenticated again under
// current trust and never changes the on-disk generation.
func (c catalogService) refresh(ctx context.Context, dir *os.File, sources []source) (catalogIndex, []map[string]string) {
	result := catalogIndex{modules: map[string][]release{}}
	problems := []map[string]string{}
	issue := func(src source, err error) {
		problems = append(problems, map[string]string{"repository": src.ID, "error": err.Error()})
	}
	type fetched struct {
		gen   generation
		index catalogIndex
		err   error
	}
	fetchedBySource := make([]fetched, len(sources))
	// Sources have independent I/O. A slow source must not consume the
	// entire request budget before later sources are contacted.
	var wg sync.WaitGroup
	for i, src := range sources {
		wg.Go(func() {
			gen, err := c.fetch(ctx, src.URL)
			var index catalogIndex
			if err == nil {
				index, err = c.readGeneration(gen, src)
			}
			fetchedBySource[i] = fetched{gen, index, err}
		})
	}
	wg.Wait()
	// Publish and merge strictly in configured order, irrespective of fetch order.
	for i, src := range sources {
		cache := catalogCacheName(src.ID)
		gen, index, err := fetchedBySource[i].gen, fetchedBySource[i].index, fetchedBySource[i].err
		if err == nil {
			raw, _ := json.Marshal(gen)
			err = atomicAt(dir, cache, raw, 0600, c.owner)
		}
		if err != nil {
			issue(src, err)
			cached, readErr := readOwnedAt(dir, cache, c.owner, 3<<20)
			var previous generation
			if readErr != nil || systemops.Decode(cached, &previous) != nil {
				continue
			}
			index, readErr = c.readGeneration(previous, src)
			if readErr != nil {
				continue
			}
		}
		for _, id := range index.order {
			if _, found := result.modules[id]; found {
				issue(src, reject("Duplicate module ID: "+id))
				continue
			}
			result.order = append(result.order, id)
			result.modules[id] = index.modules[id]
		}
	}
	return result, problems
}

func catalogCacheName(id string) string { return ".catalog-" + id + ".json" }

func (c catalogService) query(ctx context.Context, view string) (json.RawMessage, error) {
	dir, err := c.catalogLock(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err = c.repairSources(dir); err != nil {
		return nil, err
	}
	configured, err := c.sources()
	if err != nil {
		return nil, err
	}
	if view == "module-sources" {
		return json.Marshal(map[string]any{"sources": configured})
	}
	if err = c.refreshCore(); err != nil {
		return nil, err
	}
	installed, err := c.registry()
	if err != nil {
		return nil, err
	}
	index, problems := c.refresh(ctx, dir, sourceSpecs(configured))
	available := []Manifest{}
	for _, id := range index.order {
		releases := index.modules[id]
		if len(releases) == 0 {
			continue
		}
		entry := releases[0]
		reason := ""
		if err = validateManifest(entry.manifest, c.core, c.architecture, true); err != nil {
			reason = err.Error()
			for _, candidate := range releases[1:] {
				if validateManifest(candidate.manifest, c.core, c.architecture, true) == nil {
					entry = candidate
					reason = ""
					break
				}
			}
		}
		m := Manifest{}
		for k, v := range entry.manifest {
			m[k] = v
		}
		update := false
		if current := installed[id]; current != nil {
			if text(current, "signer") != text(m, "signer") {
				reason = "Installed module belongs to another publisher"
			}
			n, err := compareVersions(text(m, "version"), text(current, "version"))
			if err != nil {
				return nil, err
			}
			update = n > 0
		}
		m["requiredBy"], m["enabled"], m["reason"], m["repository"], m["updateAvailable"] = []string{}, false, reason, text(entry.raw, "repository"), update
		available = append(available, m)
	}
	return json.Marshal(map[string]any{"available": available, "errors": problems})
}

// Flock is on the trusted state directory, separate from lifecycle locks.
func (c catalogService) catalogLock(ctx context.Context, r *systemops.Reporter) (*os.File, error) {
	dir, err := trustedDirectory(c.root, c.owner)
	if err != nil {
		return nil, err
	}
	if err = waitLifecycleLock(ctx, dir, r); err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

func unlinkCatalogFile(dir *os.File, name string) error {
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return dir.Sync()
}
