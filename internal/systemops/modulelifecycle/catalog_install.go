package modulelifecycle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
)

// Assemble only inspected single-module receipts. prepare opens the resulting
// archive once; its descriptor survives removal of the private temporary path.
func (s lifecycle) catalogInstall(ctx context.Context, selection *prepared, name string) (*prepared, error) {
	var total int64
	for _, entry := range selection.entries {
		size, _ := integer(entry["size"])
		total += int64(size)
		if total > maxArchive {
			return nil, reject("Combined module download exceeds size limit")
		}
	}
	if filepath.Base(name) != name || name == "" {
		return nil, reject("Invalid account")
	}
	dir, err := os.MkdirTemp("", "panasms-catalog-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	s.uploads = dir
	const token = "00000000000000000000000000000000"
	file, err := os.OpenFile(filepath.Join(dir, name+"-"+token+".zip"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	header, err := writer.Create("bundle.json")
	if err != nil {
		return nil, err
	}
	if err = json.NewEncoder(header).Encode(Manifest{"root": selection.target}); err != nil {
		return nil, err
	}
	for _, id := range names(selection.entries) {
		entry := selection.entries[id]
		size, _ := integer(entry["size"])
		raw, err := s.fetchCatalog(ctx, text(entry, "url"), int64(size))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		if int64(len(raw)) != int64(size) || hex.EncodeToString(sum[:]) != entry["sha256"] {
			return nil, reject("Module archive checksum mismatch: " + id)
		}
		part, err := inspectBundle(bytes.NewReader(raw), int64(len(raw)), s.core, s.architecture, func(id string) (ed25519.PublicKey, error) { return readPublicKey(s.keys, id, s.owner) })
		if err != nil {
			return nil, err
		}
		if part.root != id || len(part.manifests) != 1 || !reflect.DeepEqual(part.manifests[id], releaseManifest(entry)) {
			return nil, reject("Archive does not match module catalog")
		}
		for _, path := range names(part.files) {
			if path != "bundle.json" {
				if err = writer.Copy(part.files[path]); err != nil {
					return nil, err
				}
			}
		}
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	plan, err := s.prepare(ctx, "module.install", map[string]any{"upload": token}, name)
	if err != nil {
		return nil, err
	}
	if !registryEqual(plan.installed, selection.installed) {
		plan.archive.Close()
		return nil, reject("State has changed. Review a new operation plan.")
	}
	plan.uploadName = ""
	return plan, nil
}
