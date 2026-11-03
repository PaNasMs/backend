package modulelifecycle

import (
	"sort"
)

func names[T any](items map[string]T) []string {
	result := make([]string, 0, len(items))
	for key := range items {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func dependencies(m Manifest) (map[string]string, error) {
	values, ok := object(m, "dependencies")
	if !ok {
		return nil, reject("Invalid dependencies")
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		constraint, ok := value.(string)
		if !ok {
			return nil, reject("Invalid version constraint")
		}
		result[key] = constraint
	}
	return result, nil
}

func resolve(requested string, available, installed Registry) ([]string, error) {
	visiting, visited := map[string]bool{}, map[string]bool{}
	order := []string{}
	var visit func(string, string) error
	visit = func(id, constraint string) error {
		if visiting[id] {
			return reject("Dependency cycle: " + id)
		}
		candidate, supplied := available[id]
		if !supplied {
			candidate = installed[id]
		}
		if candidate == nil {
			return reject("Missing module " + id + ". Upload an archive containing this dependency.")
		}
		if constraint != "" {
			match, err := satisfies(text(candidate, "version"), constraint)
			if err != nil {
				return err
			}
			if !match {
				return reject("Incompatible dependency version for " + id + ": requires " + constraint)
			}
		}
		if before := installed[id]; supplied && before != nil {
			if text(candidate, "signer") != text(before, "signer") {
				return reject("Module publisher differs from the installed publisher: " + id)
			}
			comparison, err := compareVersions(text(candidate, "version"), text(before, "version"))
			if err != nil {
				return err
			}
			if comparison < 0 {
				return reject("Module downgrade is not supported: " + id)
			}
		}
		if visited[id] {
			return nil
		}
		visiting[id] = true
		deps, err := dependencies(candidate)
		if err != nil {
			return err
		}
		for _, dependency := range names(deps) {
			if err = visit(dependency, deps[dependency]); err != nil {
				return err
			}
		}
		delete(visiting, id)
		visited[id] = true
		if enabled, _ := candidate["enabled"].(bool); supplied || !enabled {
			order = append(order, id)
		}
		return nil
	}
	if err := visit(requested, ""); err != nil {
		return nil, err
	}
	future := Registry{}
	for id, item := range installed {
		future[id] = item
	}
	for _, id := range order {
		if item := available[id]; item != nil {
			future[id] = item
		}
	}
	for _, id := range names(future) {
		deps, err := dependencies(future[id])
		if err != nil {
			return nil, err
		}
		for _, dependency := range names(deps) {
			candidate := future[dependency]
			match := false
			if candidate != nil {
				match, err = satisfies(text(candidate, "version"), deps[dependency])
				if err != nil {
					return nil, err
				}
			}
			if !match {
				return nil, reject("Update would break a dependency of module " + id + " on " + dependency)
			}
		}
	}
	return order, nil
}

func dependents(target string, installed Registry) ([]string, error) {
	result := []string{}
	for _, id := range names(installed) {
		if id == target {
			continue
		}
		deps, err := dependencies(installed[id])
		if err != nil {
			return nil, err
		}
		if _, found := deps[target]; found {
			result = append(result, id)
		}
	}
	return result, nil
}
