package modulelifecycle

import (
	"reflect"
	"strings"
	"testing"
)

func dependencyFixture(version string, enabled bool, deps map[string]any) Manifest {
	return Manifest{"version": version, "enabled": enabled, "dependencies": deps, "signer": "official"}
}

func TestDependencyOrderMissingCycleAndDisabledDependency(t *testing.T) {
	app := dependencyFixture("1.0.0", false, map[string]any{"dep": ">=1.0.0"})
	dep := dependencyFixture("1.1.0", false, map[string]any{})
	for _, installed := range []Registry{{}, {"dep": dep}} {
		available := Registry{"app": app}
		if len(installed) == 0 {
			available["dep"] = dep
		}
		order, err := resolve("app", available, installed)
		if err != nil || !reflect.DeepEqual(order, []string{"dep", "app"}) {
			t.Fatal(order, err)
		}
	}
	if _, err := resolve("app", Registry{"app": app}, Registry{}); err == nil || !strings.Contains(err.Error(), "Missing module dep") {
		t.Fatal(err)
	}
	dep["dependencies"] = map[string]any{"app": ">=1.0.0"}
	if _, err := resolve("app", Registry{"app": app, "dep": dep}, Registry{}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatal(err)
	}
}

func TestDependencyPublisherDowngradeAndReverseConstraint(t *testing.T) {
	old := dependencyFixture("1.2.0", true, map[string]any{})
	for _, change := range []Manifest{dependencyFixture("1.1.0", true, map[string]any{}), {"version": "1.3.0", "signer": "other"}} {
		if _, err := resolve("dep", Registry{"dep": change}, Registry{"dep": old}); err == nil {
			t.Fatal("publisher change or downgrade accepted")
		}
	}
	installed := Registry{"dep": old, "app": dependencyFixture("1.0.0", true, map[string]any{"dep": "<2.0.0"})}
	if _, err := resolve("dep", Registry{"dep": dependencyFixture("2.0.0", true, map[string]any{})}, installed); err == nil || !strings.Contains(err.Error(), "break a dependency") {
		t.Fatal(err)
	}
	if _, err := resolve("dep", Registry{"dep": dependencyFixture("1.3.0", true, map[string]any{})}, installed); err != nil {
		t.Fatal(err)
	}
	blocked, err := dependents("dep", installed)
	if err != nil || !reflect.DeepEqual(blocked, []string{"app"}) {
		t.Fatal(blocked, err)
	}
}

func TestDependencyOrderingIsDeterministicAndExistingEnabledIsNotRestarted(t *testing.T) {
	available := Registry{"app": dependencyFixture("1.0.0", false, map[string]any{"beta": ">=1.0.0", "alpha": ">=1.0.0"}), "beta": dependencyFixture("1.0.0", false, map[string]any{})}
	installed := Registry{"alpha": dependencyFixture("1.0.0", true, map[string]any{})}
	for index := 0; index < 20; index++ {
		got, err := resolve("app", available, installed)
		if err != nil || !reflect.DeepEqual(got, []string{"beta", "app"}) {
			t.Fatal(got, err)
		}
	}
}
