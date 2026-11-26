package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"maps"
	"os"
	"panasms.local/backend/internal/systemops"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const sourceFile = "module-sources.json"
const sourceIntent = "module-sources.pending.json"

func officialSource() Manifest {
	return Manifest{"id": "panasms-official", "url": "https://panasms.github.io/module-registry/", "official": true, "signers": []any{"panasms-local", "panasms-ci"}}
}
func sourceSigners(m Manifest) ([]string, error) {
	items, ok := m["signers"].([]any)
	if !ok || len(items) == 0 {
		return nil, reject("Invalid repository publishers")
	}
	ids := make([]string, 0, len(items))
	for _, v := range items {
		id, _ := v.(string)
		if !signerPattern.MatchString(id) {
			return nil, reject("Invalid repository publisher")
		}
		ids = append(ids, id)
	}
	return ids, nil
}
func (s lifecycle) configDir() (*os.File, error) {
	return trustedDirectory(filepath.Dir(s.keys), s.owner)
}
func (s lifecycle) sources() ([]Manifest, error) {
	dir, err := s.configDir()
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return s.sourcesAt(dir)
}
func (s lifecycle) sourcesAt(dir *os.File) ([]Manifest, error) {
	raw, err := readOwnedAt(dir, sourceFile, s.owner, 1<<20)
	return parseSources(raw, err)
}
func parseSources(raw []byte, err error) ([]Manifest, error) {
	if errors.Is(err, os.ErrNotExist) {
		return []Manifest{officialSource()}, nil
	}
	if err != nil {
		return nil, err
	}
	var rows []Manifest
	if systemops.Decode(raw, &rows) != nil || rows == nil || len(rows) > 16 {
		return nil, reject("Invalid module repository configuration")
	}
	for _, m := range rows {
		if _, err := sourceSigners(m); err != nil {
			return nil, err
		}
		if _, err := catalogURL(text(m, "url"), false); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func sourcePublic(raw []byte) (ed25519.PublicKey, string, error) {
	block, rest := pem.Decode(raw)
	if block != nil && block.Type == "PUBLIC KEY" && strings.TrimSpace(string(rest)) == "" {
		v, e := x509.ParsePKIXPublicKey(block.Bytes)
		if k, ok := v.(ed25519.PublicKey); e == nil && ok {
			sum := sha256.Sum256(block.Bytes)
			return k, hex.EncodeToString(sum[:]), nil
		}
	}
	return nil, "", reject("The repository must use an Ed25519 public key")
}
func (s lifecycle) fetchCatalog(ctx context.Context, url string, limit int64) ([]byte, error) {
	if s.catalogFetch != nil {
		return s.catalogFetch(ctx, url, limit)
	}
	return downloadCatalog(ctx, url, limit)
}
func (s lifecycle) discover(ctx context.Context, value string) (Manifest, []byte, error) {
	u, err := catalogURL(value, false)
	if err != nil {
		return nil, nil, err
	}
	base := strings.TrimRight(u.String(), "/") + "/"
	official := officialSource()
	if base == official["url"] {
		return official, nil, nil
	}
	env, err := s.fetchCatalog(ctx, base+"catalog.sig", 4096)
	if err != nil {
		return nil, nil, err
	}
	var sig catalogEnvelope
	if json.Unmarshal(env, &sig) != nil || !signerPattern.MatchString(sig.Signer) || strings.HasPrefix(sig.Signer, "panasms-") {
		return nil, nil, reject("Choose a unique repository publisher ID")
	}
	raw, err := s.fetchCatalog(ctx, base+"keys/"+sig.Signer+".pem", 8192)
	if err != nil {
		return nil, nil, err
	}
	key, fp, err := sourcePublic(raw)
	if err != nil {
		return nil, nil, err
	}
	dir, err := trustedDirectory(s.keys, s.owner)
	if err != nil {
		return nil, nil, err
	}
	defer dir.Close()
	previous, err := readOwnedAt(dir, sig.Signer+".pem", s.owner, 8192)
	if err == nil {
		_, old, e := sourcePublic(previous)
		if e != nil || old != fp {
			return nil, nil, reject("This publisher ID already uses another public key")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	catalog, err := s.fetchCatalog(ctx, base+"catalog.json", 2<<20)
	if err != nil {
		return nil, nil, err
	}
	if err = verifyCatalog(catalog, env, []string{sig.Signer}, func(string) (ed25519.PublicKey, error) { return key, nil }); err != nil {
		return nil, nil, err
	}
	var doc struct {
		ID            string
		SchemaVersion int
	}
	if json.Unmarshal(catalog, &doc) != nil || doc.SchemaVersion != 1 || identifier(doc.ID) != nil || doc.ID == official["id"] {
		return nil, nil, reject("Unsupported module catalog format")
	}
	return Manifest{"id": doc.ID, "url": base, "signers": []any{sig.Signer}, "fingerprint": fp, "official": false}, raw, nil
}

// sourceChange is the durable intent of one repository change. Add and
// Withdraw name the change itself, so a replay applies it to the current
// configuration and keeps independent updates made meanwhile. Sources is the
// full snapshot that versions without Add/Withdraw replay; it is kept for them.
type sourceChange struct {
	Sources          []Manifest
	Publisher        string
	Key              []byte
	Remove           bool              // Legacy pending single-publisher removal.
	RemovePublishers []string          `json:",omitempty"`
	RemovePEMHashes  map[string]string `json:",omitempty"` // Absent on legacy intents.
	Add              Manifest          `json:",omitempty"`
	Withdraw         string            `json:",omitempty"`
}

// syncDir makes directory entries durable. Tests replace it to fail a sync.
var syncDir = func(dir *os.File) error { return dir.Sync() }

// An empty digest denotes a missing file, not a wildcard.
func (s lifecycle) pemHash(keys *os.File, publisher string) (string, error) {
	raw, err := readOwnedAt(keys, publisher+".pem", s.owner, 8192)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (s lifecycle) prepareSource(ctx context.Context, action string, p map[string]any) (*prepared, error) {
	existing, err := s.sources()
	if err != nil {
		return nil, err
	}
	var source Manifest
	var details []string
	change := sourceChange{Sources: []Manifest{}}
	if action == "module.source-add" {
		var raw []byte
		source, raw, err = s.discover(ctx, text(p, "url"))
		if err != nil {
			return nil, err
		}
		if len(existing) >= 16 {
			return nil, reject("At most 16 module repositories are supported")
		}
		for _, m := range existing {
			if m["id"] == source["id"] || m["url"] == source["url"] {
				return nil, reject("This module repository is already configured")
			}
		}
		ids, _ := sourceSigners(source)
		details = []string{text(source, "url"), "Publisher: " + strings.Join(ids, ", ")}
		if fp := text(source, "fingerprint"); fp != "" {
			if prev := text(p, "keyFingerprint"); prev != "" && prev != fp {
				return nil, reject("Repository signing key changed. Review the repository again.")
			}
			p = maps.Clone(p)
			p["keyFingerprint"] = fp
			details = append(details, "SHA256: "+fp, "Trust this publisher to provide executable NAS modules")
			change.Publisher, change.Key = ids[0], raw
		}
		change.Sources = append(slices.Clone(existing), source)
		change.Add = source
	} else {
		for _, m := range existing {
			if m["id"] == text(p, "target") {
				source = m
			} else {
				change.Sources = append(change.Sources, m)
			}
		}
		if source == nil {
			return nil, reject("Module repository not found")
		}
		change.Withdraw = text(source, "id")
		ids, _ := sourceSigners(source)
		used := map[string]bool{}
		for _, m := range change.Sources {
			signers, _ := sourceSigners(m)
			for _, id := range signers {
				used[id] = true
			}
		}
		for _, id := range ids {
			if !used[id] && !strings.HasPrefix(id, "panasms-") {
				change.RemovePublishers = append(change.RemovePublishers, id)
			}
		}
		details = []string{text(source, "url"), "Installed modules are retained"}
		if len(change.RemovePublishers) > 0 {
			keys, err := trustedDirectory(s.keys, s.owner)
			if err != nil {
				return nil, err
			}
			defer keys.Close()
			change.RemovePEMHashes = make(map[string]string)
			for _, id := range change.RemovePublishers {
				hash, err := s.pemHash(keys, id)
				if err != nil {
					return nil, err
				}
				change.RemovePEMHashes[id] = hash
				if hash == "" {
					details = append(details, id+": no publisher key file")
				} else {
					details = append(details, id+" PEM SHA256: "+hash)
				}
			}
		}
	}
	identity := []any{existing, source}
	if change.RemovePEMHashes != nil {
		identity = append(identity, change.RemovePEMHashes)
	}
	fp, err := planFingerprint(action, p, identity)
	if err != nil {
		return nil, err
	}
	preview := Manifest{"target": source["id"], "confirmation": source["id"], "details": details, "fingerprint": fp}
	if action == "module.source-add" {
		preview["publisherFingerprint"] = source["fingerprint"]
	} else {
		preview["removePEMHashes"] = change.RemovePEMHashes
	}
	result, err := json.Marshal(preview)
	return &prepared{target: text(source, "id"), fingerprint: fp, result: result, source: &change}, err
}

// Replay a durable, already-authorized decision. The module lock serializes
// writers. Add the key before the source; remove a key only after its source.
// The change is merged into the current configuration, so sources and keys
// updated independently since the intent was written survive the replay.
// Every step syncs its directory even when the content is already in place:
// an earlier attempt may have stopped after a rename but before its sync.
func (s lifecycle) finishSource(dir *os.File, c sourceChange) error {
	if c.Sources == nil {
		return reject("Invalid repository transaction")
	}
	if c.Publisher != "" && (!signerPattern.MatchString(c.Publisher) || strings.HasPrefix(c.Publisher, "panasms-")) {
		return reject("Invalid repository publisher")
	}
	removals := c.RemovePublishers
	if c.Remove {
		removals = append(removals, c.Publisher)
	}
	for _, id := range removals {
		if !signerPattern.MatchString(id) || strings.HasPrefix(id, "panasms-") {
			return reject("Invalid repository publisher")
		}
	}
	if err := s.finishSourceStages(dir); err != nil {
		return err
	}
	before, readErr := readOwnedAt(dir, sourceFile, s.owner, 1<<20)
	current, err := parseSources(before, readErr)
	if err != nil {
		return err
	}
	merged, changed, err := mergeSources(current, c)
	if err != nil {
		return err
	}
	// The key is needed when this change adds its source now or added it in
	// an earlier attempt. An independent row for the same ID or URL keeps the
	// keys it already has.
	needKey := c.Add == nil || changed || slices.ContainsFunc(current, func(m Manifest) bool {
		return text(m, "id") == text(c.Add, "id") && text(m, "url") == text(c.Add, "url")
	})
	if len(c.Key) > 0 && needKey {
		if _, _, err := sourcePublic(c.Key); err != nil {
			return err
		}
		keys, err := trustedDirectory(s.keys, s.owner)
		if err != nil {
			return err
		}
		defer keys.Close()
		placed, err := s.placeKey(keys, c.Publisher, c.Key)
		if err != nil {
			return err
		}
		if !placed && c.Add != nil && changed {
			// An independent update gave this publisher another key. Keep
			// it and leave the source out: it was reviewed with this key.
			merged, changed = current, false
		}
	}
	if changed {
		raw, err := json.Marshal(merged)
		if err != nil {
			return err
		}
		if err = s.publishSources(dir, before, readErr == nil, raw); err != nil {
			var renamed *renamedSyncError
			if c.Add != nil && errors.As(err, &renamed) {
				return reject("The added repository is visible, but the configuration directory could not be synced. Recover the recorded transaction to confirm the change.")
			}
			return err
		}
	} else if err = syncDir(dir); err != nil {
		return err
	}
	if len(removals) > 0 {
		keys, err := trustedDirectory(s.keys, s.owner)
		if err != nil {
			return err
		}
		defer keys.Close()
		used := map[string]bool{}
		for _, m := range merged {
			signers, _ := sourceSigners(m)
			for _, id := range signers {
				used[id] = true
			}
		}
		for _, id := range removals {
			if used[id] {
				continue // An independent source trusts this publisher now.
			}
			if c.RemovePEMHashes != nil {
				if err := s.retirePublisherKey(keys, id, c.RemovePEMHashes[id]); err != nil {
					return err
				}
				continue
			}
			if err = os.Remove(filepath.Join(keys.Name(), id+".pem")); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err = syncDir(keys); err != nil {
			return err
		}
	}
	return removeCatalogFile(dir, sourceIntent)
}

// Move the file out of the signer lookup namespace before deciding whether
// to delete it. Comparing at the live path and then unlinking could delete a
// different file. A crash after rename leaves at worst an untrusted backup.
func (s lifecycle) retirePublisherKey(keys *os.File, id, approved string) error {
	backup := id + ".withdrawn-" + rand.Text()
	fd := int(keys.Fd())
	err := unix.Renameat2(fd, id+".pem", fd, backup, unix.RENAME_NOREPLACE)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := readOwnedAt(keys, backup, s.owner, 8192)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != approved {
		log.Printf("Publisher %s key changed since review; preserved without trust at %s", id, filepath.Join(keys.Name(), backup))
		return nil
	}
	return unix.Unlinkat(fd, backup, 0)
}

// mergeSources applies the recorded change to the current rows. An intent
// without Add or Withdraw comes from an older version and carries only the
// snapshot it was planned against.
func mergeSources(current []Manifest, c sourceChange) (merged []Manifest, changed bool, err error) {
	switch {
	case c.Add != nil && c.Withdraw != "":
		return nil, false, reject("Invalid repository transaction")
	case c.Add != nil:
		id, url := text(c.Add, "id"), text(c.Add, "url")
		if identifier(id) != nil {
			return nil, false, reject("Invalid repository transaction")
		}
		if _, err = sourceSigners(c.Add); err != nil {
			return nil, false, err
		}
		if _, err = catalogURL(url, false); err != nil {
			return nil, false, err
		}
		for _, m := range current {
			if text(m, "id") == id || text(m, "url") == url {
				// Either this change was already applied or an independent
				// update configured the repository; keep the current row.
				return current, false, nil
			}
		}
		if len(current) >= 16 {
			// Independent additions filled the list; they win.
			return current, false, nil
		}
		return append(slices.Clone(current), c.Add), true, nil
	case c.Withdraw != "":
		merged = []Manifest{}
		for _, m := range current {
			if text(m, "id") == c.Withdraw {
				changed = true
			} else {
				merged = append(merged, m)
			}
		}
		return merged, changed, nil
	}
	return c.Sources, true, nil
}

// placeKey installs the authorized key unless one is present. It reports
// whether the publisher now uses that key; a different key is an independent
// update and stays in place.
func (s lifecycle) placeKey(keys *os.File, publisher string, key []byte) (bool, error) {
	previous, err := readOwnedAt(keys, publisher+".pem", s.owner, 8192)
	if errors.Is(err, os.ErrNotExist) {
		return true, atomicAt(keys, publisher+".pem", key, 0644, s.owner)
	}
	if err != nil {
		return false, err
	}
	_, want, _ := sourcePublic(key)
	_, have, e := sourcePublic(previous)
	return e == nil && have == want, syncDir(keys)
}
func removeCatalogFile(dir *os.File, name string) error {
	err := os.Remove(filepath.Join(dir.Name(), name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(dir)
}
func (s lifecycle) pendingSource() (*sourceChange, error) {
	if s.keys == "" {
		return nil, nil
	}
	dir, err := s.configDir()
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	raw, err := readOwnedAt(dir, sourceIntent, s.owner, 2<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c sourceChange
	if err = json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
