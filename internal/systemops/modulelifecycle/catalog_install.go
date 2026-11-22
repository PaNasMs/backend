package modulelifecycle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type catalogInstallPlan struct {
	target, fingerprint string
	chosen              map[string]release
	order               []string
	installed           Registry
	details             []string
}

func (c catalogService) selectRelease(ctx context.Context, dir *os.File, p map[string]any) (catalogInstallPlan, error) {
	var out catalogInstallPlan
	out.target = text(p, "target")
	if err := identifier(out.target); err != nil {
		return out, err
	}
	requested := text(p, "version")
	if _, err := parseVersion(requested); err != nil {
		return out, err
	}
	if err := c.refreshCore(); err != nil {
		return out, err
	}
	configured, err := c.sources()
	if err != nil {
		return out, err
	}
	index, _, err := c.refresh(ctx, dir, sourceSpecs(configured))
	if err != nil {
		return out, err
	}
	out.installed, err = c.registry()
	if err != nil {
		return out, err
	}
	var order []string
	out.chosen, out.order, order, err = c.solveCatalog(ctx, index, out.installed, out.target, requested)
	if err != nil {
		return out, err
	}
	selected := map[string]any{}
	out.details = []string{}
	for _, id := range out.order {
		entry := out.chosen[id]
		selected[id] = entry.raw
		out.details = append(out.details, "Install: "+text(entry.manifest, "title")+" "+text(entry.manifest, "version"))
	}
	for _, id := range order {
		if err = requireIdle(ctx, out.installed[id], c.health, c.run); err != nil {
			return out, err
		}
	}
	out.fingerprint, err = planFingerprint("module.catalog-install", p, []any{selected, out.installed})
	return out, err
}

const catalogStage = ".catalog-stage"
const stagedToken = "00000000000000000000000000000000"
const stageOwner = "catalog" // Internal upload namespace, never exposed through the API.
const stageArchive = stageOwner + "-" + stagedToken + ".zip"

func (c catalogService) cleanCatalogStage(ctx context.Context) error {
	dir, err := trustedDirectory(filepath.Join(c.root, catalogStage), c.owner)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	removed, err := removeCatalogFile(dir, stageArchive)
	if changed, _ := ctx.Value(sourceRepairKey{}).(*bool); removed && changed != nil {
		*changed = true
	}
	return err
}

func (c catalogService) stageCatalogInstall(ctx context.Context, dir *os.File, plan catalogInstallPlan, r *systemops.Reporter) error {
	var total int64
	for _, entry := range plan.chosen {
		total += entry.size
		if total > maxArchive {
			return reject("Combined module download exceeds size limit")
		}
	}
	if err := c.cleanCatalogStage(ctx); err != nil {
		return err
	}
	if err := unix.Mkdirat(int(dir.Fd()), catalogStage, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	stage, err := trustedDirectory(filepath.Join(c.root, catalogStage), c.owner)
	if err != nil {
		return err
	}
	defer stage.Close()
	fd, err := unix.Openat(int(stage.Fd()), stageArchive, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	output := os.NewFile(uintptr(fd), stageArchive)
	defer output.Close()
	merged := zip.NewWriter(output)
	decl, err := merged.Create("bundle.json")
	if err != nil {
		return err
	}
	if err = json.NewEncoder(decl).Encode(map[string]string{"root": plan.target}); err != nil {
		return err
	}
	for _, id := range plan.order {
		if err = checkpoint(ctx, r); err != nil {
			return err
		}
		entry := plan.chosen[id]
		if r != nil {
			r.Stage("Downloading module: " + id)
		}
		raw, err := systemops.WithCancellation(ctx, r, func(ctx context.Context) ([]byte, error) {
			return c.download(ctx, entry.url, entry.size, archiveDownload)
		})
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		if int64(len(raw)) != entry.size || hex.EncodeToString(sum[:]) != entry.checksum {
			return reject("Module archive checksum mismatch: " + id)
		}
		archived, err := inspectBundle(bytes.NewReader(raw), entry.size, c.core, c.architecture, func(signer string) (ed25519.PublicKey, error) {
			if signer != text(entry.manifest, "signer") {
				return nil, reject("Archive publisher does not match module catalog")
			}
			return c.activePublisherKey(signer)
		})
		if err != nil {
			return err
		}
		if archived.root != id || !registryEqual(archived.manifests, Registry{id: entry.manifest}) {
			return reject("Archive does not match module catalog")
		}
		for _, name := range names(archived.files) {
			if name != "bundle.json" {
				if err = merged.Copy(archived.files[name]); err != nil {
					return err
				}
			}
		}
	}
	if err = merged.Close(); err != nil {
		return err
	}
	return output.Sync()
}

func (c catalogService) install(ctx context.Context, dir *os.File, plan catalogInstallPlan, r *systemops.Reporter, authorize func() error) (result json.RawMessage, err error) {
	lc := c.lifecycle
	lc.uploads = filepath.Join(c.root, catalogStage)
	lc.catalogCommitWarnings = true
	delegated := false
	defer func() {
		if err != nil && !delegated {
			err = systemops.BeforeMutation(err)
		}
		cancellable(r, false)
	}()
	defer func() {
		if cleanupErr := c.cleanCatalogStage(ctx); cleanupErr != nil {
			const warning = "Catalog staging cleanup is incomplete."
			if err == nil {
				// The delegated lifecycle has already committed; never replace
				// its successful result with a staging cleanup error.
				result = catalogWarning(result, warning)
			} else if r != nil {
				r.Stage(warning)
			}
		}
	}()
	if err = lc.refreshCore(); err != nil {
		return nil, err
	}
	c.core = lc.core
	if err = c.stageCatalogInstall(ctx, dir, plan, r); err != nil {
		return nil, err
	}
	params := map[string]any{"upload": stagedToken}
	native, err := lc.prepare(ctx, "module.install", params, stageOwner)
	if err != nil {
		return nil, err
	}
	native.archive.Close()
	if !registryEqual(native.installed, plan.installed) {
		return nil, reject("State has changed. Review a new operation plan.")
	}
	delegated = true
	return lc.execute(ctx, "module.install", params, stageOwner, native.fingerprint, r, authorize)
}

// catalogWarning augments a successful lifecycle result without changing its
// message or discarding any warning already reported by the lifecycle.
func catalogWarning(raw json.RawMessage, warning string) json.RawMessage {
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return raw
	}
	var warnings []string
	_ = json.Unmarshal(body["warnings"], &warnings)
	body["warnings"], _ = json.Marshal(append(warnings, warning))
	result, _ := json.Marshal(body)
	return result
}
