package modulelifecycle

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"panasms.local/backend/internal/systemops"
	"regexp"
	"slices"
	"sort"
)

type releaseSet map[string][]Manifest

func releaseManifest(entry Manifest) Manifest { m, _ := entry["manifest"].(map[string]any); return m }

var officialRepo = regexp.MustCompile(`^https://github\.com/PaNasMs/[a-z][a-z0-9-]*/releases/download/`)
var catalogHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s lifecycle) readCatalog(ctx context.Context, src Manifest) (releaseSet, error) {
	base := text(src, "url")
	raw, err := s.fetchCatalog(ctx, base+"catalog.json", 2<<20)
	if err != nil {
		return nil, err
	}
	env, err := s.fetchCatalog(ctx, base+"catalog.sig", 4096)
	if err != nil {
		return nil, err
	}
	ids, err := sourceSigners(src)
	if err != nil {
		return nil, err
	}
	if err = verifyCatalog(raw, env, ids, func(id string) (ed25519.PublicKey, error) { return readPublicKey(s.keys, id, s.owner) }); err != nil {
		return nil, err
	}
	var doc struct {
		ID            string
		SchemaVersion int
		Modules       []struct {
			ID       string
			Releases []Manifest
		}
	}
	if systemops.Decode(raw, &doc) != nil || doc.SchemaVersion != 1 || doc.ID != src["id"] || doc.Modules == nil {
		return nil, reject("Unsupported module catalog format")
	}
	out := releaseSet{}
	for _, item := range doc.Modules {
		id := item.ID
		if err = identifier(id); err != nil {
			return nil, err
		}
		if _, exists := out[id]; exists {
			return nil, reject("Duplicate module in catalog")
		}
		out[id] = []Manifest{}
		for _, e := range item.Releases {
			m := releaseManifest(e)
			if text(m, "id") != id {
				return nil, reject("Module catalog identity mismatch")
			}
			v := text(m, "version")
			if _, err = parseVersion(v); err != nil {
				return nil, err
			}
			if !slices.Contains(ids, text(m, "signer")) {
				return nil, reject("Module publisher differs from repository publisher")
			}
			u := text(e, "url")
			if _, err = catalogURL(u, false); err != nil {
				return nil, err
			}
			if src["official"] == true {
				prefix := officialRepo.FindString(u)
				if prefix == "" || u != prefix+id+"-v"+v+"/"+id+"-"+v+"-"+text(m, "architecture")+".panasms" {
					return nil, reject("Untrusted module download URL")
				}
			}
			n, ok := integer(e["size"])
			if !ok || n < 1 || n > maxArchive || !catalogHash.MatchString(text(e, "sha256")) {
				return nil, reject("Invalid module download metadata")
			}
			e["repository"] = doc.ID
			if e["channel"] == "stable" {
				out[id] = append(out[id], e)
			}
		}
		sort.SliceStable(out[id], func(i, j int) bool {
			n, _ := compareVersions(text(releaseManifest(out[id][i]), "version"), text(releaseManifest(out[id][j]), "version"))
			return n > 0
		})
	}
	return out, nil
}
func (s lifecycle) catalog(ctx context.Context) (releaseSet, []Manifest, error) {
	rows, err := s.sources()
	if err != nil {
		return nil, nil, err
	}
	out := releaseSet{}
	problems := []Manifest{}
	for _, row := range rows {
		entries, err := s.readCatalog(ctx, row)
		if err != nil {
			problems = append(problems, Manifest{"repository": row["id"], "error": err.Error()})
			continue
		}
		for _, id := range names(entries) {
			if _, exists := out[id]; exists {
				problems = append(problems, Manifest{"repository": row["id"], "error": "Duplicate module ID: " + id})
			} else {
				out[id] = entries[id]
			}
		}
	}
	return out, problems, nil
}
func CatalogQuery(ctx context.Context, view string) (json.RawMessage, error) {
	s, err := installedLifecycle()
	if err != nil {
		return nil, err
	}
	if view == "module-sources" {
		rows, err := s.sources()
		if err != nil {
			return nil, err
		}
		return json.Marshal(Manifest{"sources": rows})
	}
	return s.catalogAvailable(ctx)
}
func (s lifecycle) catalogAvailable(ctx context.Context) (json.RawMessage, error) {
	entries, problems, err := s.catalog(ctx)
	if err != nil {
		return nil, err
	}
	reg, err := s.registry()
	if err != nil {
		return nil, err
	}
	result := []Manifest{}
	for _, id := range names(entries) {
		rows := entries[id]
		if len(rows) == 0 {
			continue
		}
		entry := rows[0]
		for _, e := range rows {
			if validateManifest(releaseManifest(e), s.core, s.architecture, true) == nil {
				entry = e
				break
			}
		}
		m := maps.Clone(releaseManifest(entry))
		reason := ""
		if err := validateManifest(m, s.core, s.architecture, true); err != nil {
			reason = err.Error()
		}
		update := false
		if old := reg[id]; old != nil {
			n, e := compareVersions(text(m, "version"), text(old, "version"))
			if e != nil {
				return nil, e
			}
			update = n > 0
			if text(old, "signer") != text(m, "signer") {
				reason = "Installed module belongs to another publisher"
			}
		}
		m["reason"], m["requiredBy"], m["enabled"], m["repository"], m["updateAvailable"] = reason, []string{}, false, entry["repository"], update
		result = append(result, m)
	}
	return json.Marshal(Manifest{"available": result, "errors": problems})
}
func (s lifecycle) catalogPlan(ctx context.Context, p map[string]any) (*prepared, error) {
	target := text(p, "target")
	if err := identifier(target); err != nil {
		return nil, err
	}
	v := text(p, "version")
	if _, err := parseVersion(v); err != nil {
		return nil, err
	}
	all, _, err := s.catalog(ctx)
	if err != nil {
		return nil, err
	}
	installed, err := s.registry()
	if err != nil {
		return nil, err
	}
	chosen := Registry{}
	available := Registry{}
	visiting := map[string]bool{}
	details := []string{}
	var visit func(string, string) error
	visit = func(id, constraint string) error {
		if visiting[id] {
			return reject("Dependency cycle: " + id)
		}
		if m := available[id]; m != nil {
			if ok, _ := satisfies(text(m, "version"), constraint); !ok {
				return reject("Conflicting module dependency: " + id)
			}
			return nil
		}
		old := installed[id]
		if old != nil && id != target {
			if ok, _ := satisfies(text(old, "version"), constraint); ok {
				return nil
			}
		}
		for _, e := range all[id] {
			m := releaseManifest(e)
			if validateManifest(m, s.core, s.architecture, true) != nil {
				continue
			}
			ok, _ := satisfies(text(m, "version"), constraint)
			if !ok {
				continue
			}
			if old != nil {
				cmp, err := compareVersions(text(m, "version"), text(old, "version"))
				if err != nil || cmp < 0 || m["signer"] != old["signer"] {
					continue
				}
			}
			available[id], chosen[id], visiting[id] = m, e, true
			details = append(details, "Install: "+text(m, "title")+" "+text(m, "version"))
			deps, err := dependencies(m)
			if err != nil {
				return err
			}
			for _, dep := range names(deps) {
				if err = visit(dep, deps[dep]); err != nil {
					return err
				}
			}
			delete(visiting, id)
			return nil
		}
		return reject("No compatible module release: " + id)
	}
	if err = visit(target, "="+v); err != nil {
		return nil, err
	}
	order, err := resolve(target, available, installed)
	if err != nil {
		return nil, err
	}
	for _, id := range order {
		if err = requireIdle(ctx, installed[id], s.health, s.run); err != nil {
			return nil, err
		}
	}
	fp, err := planFingerprint("module.catalog-install", p, []any{chosen, installed})
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(Manifest{"target": target, "confirmation": target, "details": details, "fingerprint": fp})
	return &prepared{target: target, installed: installed, entries: chosen, fingerprint: fp, result: body}, err
}
