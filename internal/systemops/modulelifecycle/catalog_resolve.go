package modulelifecycle

import "context"

const catalogSearchBudget = 8192

// Each choice stays on the stack until every subsequent requirement passes.
// A later parent can therefore force an earlier choice (even a reused
// installed release) to be reconsidered. Only the winning source's releases
// are in index, in descending version order.
func (c catalogService) solveCatalog(ctx context.Context, index catalogIndex, installed Registry, target, version string) (map[string]release, []string, []string, error) {
	type requirement struct {
		id, constraint string
		root, leave    bool
		next           *requirement
	}
	assigned, available := Registry{}, Registry{}
	visiting := map[string]bool{}
	chosen := map[string]release{}
	var preorder, lifecycleOrder []string
	var why error
	budget := catalogSearchBudget
	spend := func(n int) error {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		budget -= n
		if budget < 0 {
			return reject("Module dependency search limit exceeded")
		}
		return nil
	}
	var search func(*requirement) (bool, error)
	search = func(req *requirement) (bool, error) {
		if err := spend(1); err != nil {
			return false, err
		}
		if req == nil {
			if err := spend(len(installed) + len(assigned)); err != nil {
				return false, err
			}
			var err error
			lifecycleOrder, err = resolve(target, available, installed)
			if err != nil {
				why = err
			}
			return err == nil, nil
		}
		id := req.id
		if req.leave {
			visiting[id] = false
			ok, err := search(req.next)
			visiting[id] = true
			return ok, err
		}
		if visiting[id] {
			why = reject("Dependency cycle: " + id)
			return false, nil
		}
		if m := assigned[id]; m != nil {
			match, err := satisfies(text(m, "version"), req.constraint)
			if err != nil {
				return false, err
			}
			if !match {
				why = reject("Conflicting module dependency: " + id)
				return false, nil
			}
			return search(req.next)
		}
		try := func(m Manifest, entry *release) (bool, error) {
			match, err := satisfies(text(m, "version"), req.constraint)
			if err != nil || !match {
				return false, err
			}
			deps, err := dependencies(m)
			if err != nil {
				why = err
				return false, nil
			}
			if err := spend(len(deps)); err != nil {
				return false, err
			}
			pending := &requirement{id: id, leave: true, next: req.next}
			ids := names(deps)
			for i := len(ids) - 1; i >= 0; i-- {
				dep := ids[i]
				pending = &requirement{id: dep, constraint: deps[dep], next: pending}
			}
			assigned[id], visiting[id] = m, true
			if entry != nil {
				available[id], chosen[id] = m, *entry
				preorder = append(preorder, id)
			}
			ok, err := search(pending)
			if !ok {
				delete(assigned, id)
				delete(visiting, id)
				if entry != nil {
					delete(available, id)
					delete(chosen, id)
					preorder = preorder[:len(preorder)-1]
				}
			}
			return ok, err
		}
		current := installed[id]
		why = reject("No compatible module release: " + id)
		if current != nil && !req.root {
			if ok, err := try(current, nil); ok || err != nil {
				return ok, err
			}
		}
		for _, entry := range index.modules[id] {
			if err := spend(1); err != nil {
				return false, err
			}
			if validateManifest(entry.manifest, c.core, c.architecture, true) != nil {
				continue
			}
			if current != nil {
				n, err := compareVersions(text(entry.manifest, "version"), text(current, "version"))
				if err != nil {
					return false, err
				}
				if n < 0 || text(current, "signer") != text(entry.manifest, "signer") {
					continue
				}
			}
			if ok, err := try(entry.manifest, &entry); ok || err != nil {
				return ok, err
			}
		}
		return false, nil
	}
	ok, err := search(&requirement{id: target, constraint: "=" + version, root: true})
	if err != nil {
		return nil, nil, nil, err
	}
	if !ok {
		return nil, nil, nil, why
	}
	return chosen, preorder, lifecycleOrder, nil
}
