package modulelifecycle

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func TestDebianComparisonPreservesEpochPrereleaseAndInvalidVersionFailure(t *testing.T) {
	if _, err := os.Stat("/usr/bin/dpkg"); err != nil {
		t.Skip("Debian version tool unavailable")
	}
	for _, example := range []struct {
		left, operator, right string
		want                  bool
	}{{"1:1.0", "gt", "2.0", true}, {"1.0~rc1", "ge", "1.0", false}, {"1.0-2", "ge", "1.0-1", true}, {"1.0", "gt", "1.0", false}} {
		got, err := compareDebian(context.Background(), example.left, example.operator, example.right)
		if err != nil || got != example.want {
			t.Fatal(example, got, err)
		}
	}
	if _, err := compareDebian(context.Background(), "1.0-", "ge", "1.0"); err == nil {
		t.Fatal("invalid version silently treated as older")
	}
}

func TestPackagePlanResolvesHighestMinimumPinsCandidateAndNeverMutates(t *testing.T) {
	manifests := []Manifest{{"packages": map[string]any{"liba": "1.0", "libb": "2.0"}}, {"packages": map[string]any{"liba": "1.1"}}}
	calls := [][]string{}
	run := func(_ context.Context, argv []string, options systemops.CommandOptions) ([]byte, error) {
		if options.Operation {
			t.Fatal("planning invoked package mutation")
		}
		calls = append(calls, argv)
		switch argv[0] {
		case "dpkg-query":
			if argv[len(argv)-1] == "liba" {
				return []byte("installed 1.2"), nil
			}
			return []byte("installed 1.0"), nil
		case "apt-cache":
			return []byte("libb:\n  Installed: 1.0\n  Candidate: 2.1\n"), nil
		case "apt-get":
			if !reflect.DeepEqual(argv, []string{"apt-get", "--simulate", "--no-remove", "install", "libb=2.1"}) {
				t.Fatal(argv)
			}
			return []byte("Inst libb [1.0] (2.1 Debian)\nConf libb (2.1 Debian)\n"), nil
		}
		t.Fatal(argv)
		return nil, nil
	}
	missing, changes, err := packagePlan(context.Background(), manifests, run, compareDebian)
	if err != nil || !reflect.DeepEqual(missing, []string{"libb=2.1"}) || !reflect.DeepEqual(changes, []string{"Inst libb [1.0] (2.1 Debian)"}) {
		t.Fatal(missing, changes, err)
	}
	if len(calls) != 4 {
		t.Fatal(calls)
	}
}

func TestPackagePlanRefusesUnavailableOrRemovingDependencies(t *testing.T) {
	for _, scenario := range []string{"none", "too-old", "missing-candidate", "remove"} {
		t.Run(scenario, func(t *testing.T) {
			mutating := false
			run := func(_ context.Context, argv []string, options systemops.CommandOptions) ([]byte, error) {
				if options.Operation {
					mutating = true
				}
				switch argv[0] {
				case "dpkg-query":
					return nil, nil
				case "apt-cache":
					switch scenario {
					case "none":
						return []byte("Candidate: (none)"), nil
					case "too-old":
						return []byte("Candidate: 1.0"), nil
					case "missing-candidate":
						return []byte("Installed: 2.0"), nil
					}
					return []byte("Candidate: 2.0"), nil
				case "apt-get":
					return []byte("  Remv important-package [1.0]\nInst liba (2.0)"), nil
				}
				t.Fatal(argv)
				return nil, nil
			}
			_, _, err := packagePlan(context.Background(), []Manifest{{"packages": map[string]any{"liba": "2.0"}}}, run, compareDebian)
			if err == nil || mutating {
				t.Fatal("unsafe package plan accepted", err)
			}
			if scenario == "remove" && !strings.Contains(err.Error(), "removing") {
				t.Fatal(err)
			}
		})
	}
	for _, bad := range []Manifest{{"packages": []any{}}, {"packages": map[string]any{"liba --bad": "1.0"}}, {"packages": map[string]any{"liba": "1.0; unsafe"}}} {
		if _, _, err := packagePlan(context.Background(), []Manifest{bad}, func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
			t.Fatal("invalid package input reached command")
			return nil, nil
		}, compareDebian); err == nil {
			t.Fatal("invalid OS dependency accepted", bad)
		}
	}
}
