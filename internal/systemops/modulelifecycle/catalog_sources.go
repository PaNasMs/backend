package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"os"
	"panasms.local/backend/internal/systemops"
	"path/filepath"
	"slices"
	"strings"
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
	raw, err := readOwnedAt(dir, sourceFile, s.owner, 1<<20)
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

type sourceChange struct {
	Sources   []Manifest
	Publisher string
	Key       []byte
	Remove    bool
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
		ids, _ := sourceSigners(source)
		if len(ids) == 1 && !strings.HasPrefix(ids[0], "panasms-") {
			used := false
			for _, m := range change.Sources {
				signers, _ := sourceSigners(m)
				used = used || slices.Contains(signers, ids[0])
			}
			if !used {
				change.Publisher, change.Remove = ids[0], true
			}
		}
		details = []string{text(source, "url"), "Installed modules are retained"}
	}
	fp, err := planFingerprint(action, p, []any{existing, source})
	if err != nil {
		return nil, err
	}
	result, err := json.Marshal(Manifest{"target": source["id"], "confirmation": source["id"], "details": details, "publisherFingerprint": source["fingerprint"], "fingerprint": fp})
	return &prepared{target: text(source, "id"), fingerprint: fp, result: result, source: &change}, err
}

// Replay a durable, already-authorized decision. The module lock serializes
// writers. Add the key before the source; remove a key only after its source.
func (s lifecycle) finishSource(dir *os.File, c sourceChange) error {
	if c.Sources == nil {
		return reject("Invalid repository transaction")
	}
	if c.Publisher != "" && (!signerPattern.MatchString(c.Publisher) || strings.HasPrefix(c.Publisher, "panasms-")) {
		return reject("Invalid repository publisher")
	}
	if len(c.Key) > 0 {
		if _, _, err := sourcePublic(c.Key); err != nil {
			return err
		}
		keys, err := trustedDirectory(s.keys, s.owner)
		if err != nil {
			return err
		}
		defer keys.Close()
		if err = atomicAt(keys, c.Publisher+".pem", c.Key, 0644, s.owner); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(c.Sources)
	if err != nil {
		return err
	}
	if err = atomicAt(dir, sourceFile, raw, 0600, s.owner); err != nil {
		return err
	}
	if c.Remove {
		keys, err := trustedDirectory(s.keys, s.owner)
		if err != nil {
			return err
		}
		defer keys.Close()
		if err = removeCatalogFile(keys, c.Publisher+".pem"); err != nil {
			return err
		}
	}
	return removeCatalogFile(dir, sourceIntent)
}
func removeCatalogFile(dir *os.File, name string) error {
	err := os.Remove(filepath.Join(dir.Name(), name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return dir.Sync()
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
