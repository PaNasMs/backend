package management

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/modules"
	"panasms.local/backend/internal/systemops"
)

func moduleFixture(t *testing.T, script string) (modules.Manifest, func(modules.Manifest), string) {
	t.Helper()
	previous := modules.Root
	modules.Root = t.TempDir()
	if err := os.Chmod(modules.Root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { modules.Root = previous })
	path := filepath.Join(modules.Root, "files", "bin", "server")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(script))
	m := modules.Manifest{ID: "files", API: 1, Enabled: true, Operations: "bin/server", Installation: "one", Version: "1.0.0", Files: map[string]string{"bin/server": hex.EncodeToString(sum[:])}, Actions: []string{"file.copy", "file.permissions"}, Queries: []string{"files"}}
	save := func(m modules.Manifest) {
		raw, e := json.Marshal(map[string]modules.Manifest{"files": m})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(modules.Root, "registry.json"), raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	save(m)
	return m, save, path
}

const moduleScript = `#!/bin/sh
[ "$1" = operations ] && [ "$3" = alice ] || exit 9
cat >/dev/null
case "$2" in
plan) printf '{"fingerprint":"state","confirmation":"copy","extra":"preserved"}';;
execute) printf '{"message":"done"}';;
query) printf '{"entries":[]}';;
*) exit 10;;
esac
`

func fixtureHandler(role string, changing bool) systemops.Handler {
	return moduleHandler(func(systemops.Mode, string, *systemops.Request, *systemops.Reporter) (json.RawMessage, error) {
		return nil, errors.New("unexpected core")
	}, func(string) (auth.Identity, error) {
		return auth.Identity{UID: 1000, Principal: "alice", Epoch: "epoch", Role: role}, nil
	}, func() (bool, error) { return changing, nil }, uint32(os.Geteuid()))
}
func quietReporter() *systemops.Reporter {
	return systemops.NewReporter(&bytes.Buffer{}, func(string) string { return "" })
}
func plannedRequest(t *testing.T, h systemops.Handler) *systemops.Request {
	t.Helper()
	req := &systemops.Request{Action: "file.copy", Params: map[string]any{"target": "source"}}
	raw, e := h(systemops.ModePlan, "alice", req, quietReporter())
	if e != nil {
		t.Fatal(e)
	}
	var plan map[string]any
	if e = json.Unmarshal(raw, &plan); e != nil {
		t.Fatal(e)
	}
	req.Fingerprint = plan["fingerprint"].(string)
	req.Confirmation = plan["confirmation"].(string)
	return req
}
func TestNativeModuleRoutesExactlyOnceWithoutLegacy(t *testing.T) {
	moduleFixture(t, moduleScript)
	calls := 0
	legacyCalls := 0
	invoke := route(func(context.Context, string, string, any) (json.RawMessage, error) {
		calls++
		return nil, errors.New("module failed")
	}, func(context.Context, string, string, any) (json.RawMessage, error) { legacyCalls++; return nil, nil })
	if _, err := invoke(context.Background(), "execute", "alice", Request{Action: "file.copy"}); err == nil {
		t.Fatal("failure lost")
	}
	if calls != 1 || legacyCalls != 0 {
		t.Fatalf("native=%d legacy=%d", calls, legacyCalls)
	}
}
func TestNativeModulePlanExecuteAndMemberGates(t *testing.T) {
	moduleFixture(t, moduleScript)
	h := fixtureHandler("user", false)
	req := plannedRequest(t, h)
	if req.Fingerprint == "state" {
		t.Fatal("plan not bound to installed payload")
	}
	if raw, e := h(systemops.ModeExecute, "alice", req, quietReporter()); e != nil || !bytes.Contains(raw, []byte("done")) {
		t.Fatalf("%s %v", raw, e)
	}
	if _, e := h(systemops.ModeQuery, "alice", &systemops.Request{View: "files"}, quietReporter()); e != nil {
		t.Fatal(e)
	}
	req.Action = "file.permissions"
	if _, e := h(systemops.ModePlan, "alice", req, quietReporter()); e == nil {
		t.Fatal("member privileged action allowed")
	}
	if _, e := fixtureHandler("admin", false)(systemops.ModePlan, "alice", req, quietReporter()); e != nil {
		t.Fatal(e)
	}
}
func TestNativeModuleStalePlanDisabledAndChangedPayload(t *testing.T) {
	for _, scenario := range []string{"disabled", "checksum", "version", "confirmation", "actor", "updating"} {
		t.Run(scenario, func(t *testing.T) {
			m, save, path := moduleFixture(t, moduleScript)
			h := fixtureHandler("admin", false)
			req := plannedRequest(t, h)
			switch scenario {
			case "disabled":
				m.Enabled = false
				save(m)
			case "checksum":
				os.WriteFile(path, []byte(moduleScript+"\n"), 0755)
			case "version":
				m.Version = "1.0.1"
				save(m)
			case "confirmation":
				req.Confirmation = "wrong"
			case "actor":
				req.Actor = &systemops.Actor{UID: 2000}
			case "updating":
				h = fixtureHandler("admin", true)
			}
			if _, e := h(systemops.ModeExecute, "alice", req, quietReporter()); e == nil || !systemops.Unchanged(e) {
				t.Fatalf("expected before-mutation rejection: %v", e)
			}
		})
	}
}
func TestNativeModuleRegistrationAndFilesystemRejections(t *testing.T) {
	for _, scenario := range []string{"duplicate", "core", "protocol", "symlink", "writable"} {
		t.Run(scenario, func(t *testing.T) {
			m, save, path := moduleFixture(t, moduleScript)
			switch scenario {
			case "duplicate":
				m.Actions = append(m.Actions, "file.copy")
			case "core":
				m.Actions = append(m.Actions, "user.create")
			case "protocol":
				m.Operations = "../../bin/sh"
			case "symlink":
				os.Rename(path, path+".real")
				os.Symlink(path+".real", path)
			case "writable":
				os.Chmod(path, 0777)
			}
			save(m)
			if _, e := fixtureHandler("admin", false)(systemops.ModePlan, "alice", &systemops.Request{Action: "file.copy", Params: map[string]any{}}, quietReporter()); e == nil {
				t.Fatal("unsafe module accepted")
			}
		})
	}
}
func TestNativeModuleOutputAndCancellation(t *testing.T) {
	for _, scenario := range []string{"failure", "malformed", "oversized", "cancelled", "error"} {
		t.Run(scenario, func(t *testing.T) {
			script := "#!/bin/sh\ncat >/dev/null\n"
			switch scenario {
			case "failure":
				script += "exit 8\n"
			case "malformed":
				script += "printf 'no json'\n"
			case "oversized":
				script += "head -c 4194305 /dev/zero\n"
			case "cancelled":
				script += "printf '{\"cancelled\":true}'\n"
			case "error":
				script += "printf '{\"error\":\"Destination changed\"}'\n"
			}
			_, _, path := moduleFixture(t, script)
			_, e := invokeModule(path, "execute", "alice", map[string]any{})
			if e == nil {
				t.Fatal("invalid output accepted")
			}
			if scenario == "cancelled" && !errors.Is(e, systemops.ErrCancelled) {
				t.Fatal(e)
			}
		})
	}
}
func TestNativeModuleLifecycleSharedLock(t *testing.T) {
	moduleFixture(t, moduleScript)
	lock, e := modules.Lock()
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	other, e := os.OpenFile(filepath.Join(modules.Root, ".lock"), os.O_RDWR, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	if e = unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(e, unix.EWOULDBLOCK) {
		t.Fatalf("update can replace running payload: %v", e)
	}
	lock.Close()
	if e = unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
}
func TestModuleRecoveryObservesWithoutReplaying(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "source")
	os.WriteFile(target, []byte("abc"), 0600)
	destination := filepath.Join(dir, "destination")
	holder := filepath.Join(dir, ".panasms-copy-one")
	os.Mkdir(holder, 0700)
	journal, _ := json.Marshal(map[string]string{"source": target, "destination": destination, "phase": "copying"})
	os.WriteFile(filepath.Join(holder, "transfer.json"), journal, 0600)
	req, _ := json.Marshal(systemops.Request{Action: "file.copy", Params: map[string]any{"target": target, "destination": destination}})
	var out bytes.Buffer
	if e := InspectModuleRecovery(bytes.NewReader(req), &out); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Retained transfer journal") || !strings.Contains(out.String(), "3 bytes") {
		t.Fatal(out.String())
	}
	if _, e := os.Stat(destination); !os.IsNotExist(e) {
		t.Fatal("recovery replayed copy")
	}
}

func TestNativeModuleFreshAuthorizationBeforeMutation(t *testing.T) {
	moduleFixture(t, moduleScript)
	req := plannedRequest(t, fixtureHandler("admin", false))
	calls := 0
	h := moduleHandler(nil, func(string) (auth.Identity, error) {
		calls++
		epoch := "old"
		if calls > 1 {
			epoch = "new"
		}
		return auth.Identity{UID: 1000, Role: "admin", Epoch: epoch}, nil
	}, func() (bool, error) { return false, nil }, uint32(os.Geteuid()))
	if _, e := h(systemops.ModeExecute, "alice", req, quietReporter()); e == nil || !systemops.Unchanged(e) {
		t.Fatalf("changed identity was accepted: %v", e)
	}
}
func TestNativeModuleCancellationDescriptorAndOperationEnvironment(t *testing.T) {
	_, _, path := moduleFixture(t, `#!/bin/sh
cat >/dev/null
[ "$PANASMS_OPERATION" = 1 ] || exit 12
[ "$PANASMS_CONTROL_FD" = 3 ] || exit 13
read -r value <&3
[ "$value" = cancel ] || exit 14
printf '{"cancelled":true}'
`)
	read, write, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer read.Close()
	defer write.Close()
	t.Setenv(systemops.ControlFDEnv, strconv.Itoa(int(read.Fd())))
	write.WriteString("cancel\n")
	if _, e = invokeModule(path, "execute", "alice", map[string]any{}); !errors.Is(e, systemops.ErrCancelled) {
		t.Fatal(e)
	}
	if _, e = read.Stat(); e != nil {
		t.Fatalf("parent control FD closed: %v", e)
	}
}
func TestNativeModuleCancellationBeforeExecute(t *testing.T) {
	moduleFixture(t, moduleScript)
	h := fixtureHandler("admin", false)
	req := plannedRequest(t, h)
	read, write, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer read.Close()
	defer write.Close()
	write.Write([]byte{1})
	reporter := systemops.NewReporter(&bytes.Buffer{}, func(string) string { return strconv.Itoa(int(read.Fd())) })
	if _, e = h(systemops.ModeExecute, "alice", req, reporter); !errors.Is(e, systemops.ErrCancelled) || !systemops.Unchanged(e) {
		t.Fatalf("%v", e)
	}
}

func TestReleasedFilesNativeDispatch(t *testing.T) {
	bundle := os.Getenv("PANASMS_TEST_FILES_BUNDLE")
	if bundle == "" {
		t.Skip("requires verified released Files executable and manifest")
	}
	raw, e := os.ReadFile(filepath.Join(bundle, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var released modules.Manifest
	if e = json.Unmarshal(raw, &released); e != nil {
		t.Fatal(e)
	}
	binary, e := os.ReadFile(filepath.Join(bundle, "server"))
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(binary)
	if hex.EncodeToString(sum[:]) != released.Files["bin/server"] {
		t.Fatal("released checksum mismatch")
	}
	_, save, _ := moduleFixture(t, string(binary))
	released.Enabled = true
	released.Installation = "fixture"
	save(released)
	if _, e = modules.VerifyOperation(&released, uint32(os.Geteuid())); e != nil {
		t.Fatal(e)
	}
	actor, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	h := moduleHandler(nil, func(string) (auth.Identity, error) {
		return auth.Identity{UID: os.Geteuid(), Role: "user", Principal: actor.Username}, nil
	}, func() (bool, error) { return false, nil }, uint32(os.Geteuid()))
	fixture := t.TempDir()
	target := filepath.Join(fixture, "source")
	destination := filepath.Join(fixture, "destination")
	if e = os.WriteFile(target, []byte("GO-12 isolated module fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = h(systemops.ModeQuery, actor.Username, &systemops.Request{View: "files", Target: fixture}, quietReporter()); e != nil {
		t.Fatal(e)
	}
	req := &systemops.Request{Action: "file.copy", Params: map[string]any{"target": target, "destination": destination, "conflict": ""}}
	plan, e := h(systemops.ModePlan, actor.Username, req, quietReporter())
	if e != nil {
		t.Fatal(e)
	}
	var planned struct{ Fingerprint, Confirmation string }
	if e = json.Unmarshal(plan, &planned); e != nil {
		t.Fatal(e)
	}
	req.Fingerprint = planned.Fingerprint
	req.Confirmation = planned.Confirmation
	if _, e = h(systemops.ModeExecute, actor.Username, req, quietReporter()); e != nil {
		t.Fatal(e)
	}
	content, e := os.ReadFile(destination)
	if e != nil || string(content) != "GO-12 isolated module fixture" {
		t.Fatalf("copy result %q %v", content, e)
	}
}

func TestModuleProgressDropsOversizedLineAndContinues(t *testing.T) {
	var out bytes.Buffer
	p := moduleProgress{out: &out}
	p.Write(bytes.Repeat([]byte("x"), systemops.MaxProgressLine+5))
	p.Write([]byte("\n{\"stage\":\"Copied\"}\n"))
	if out.String() != "{\"stage\":\"Copied\"}\n" {
		t.Fatal("oversized progress leaked or subsequent progress lost")
	}
}
func TestNativeModuleExecuteFailureRemainsUncertain(t *testing.T) {
	moduleFixture(t, strings.Replace(moduleScript, `printf '{"message":"done"}'`, "exit 7", 1))
	h := fixtureHandler("admin", false)
	req := plannedRequest(t, h)
	if _, e := h(systemops.ModeExecute, "alice", req, quietReporter()); e == nil || systemops.Unchanged(e) {
		t.Fatalf("mutation failure was marked unchanged: %v", e)
	}
}
