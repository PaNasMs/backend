package networkmounts

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"strings"
	"testing"
)

type fakeMounts struct {
	rows     []folders.LiveMount
	commands [][]string
	fail     string
	crash    bool
}

func executionFixture(t *testing.T) (*service, map[string]any, *fakeMounts) {
	s, p := fixture(t)
	fake := &fakeMounts{}
	s.mounts = func() ([]folders.LiveMount, error) { return append([]folders.LiveMount{}, fake.rows...), nil }
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		fake.commands = append(fake.commands, append([]string{}, args...))
		if args[0] == "mount" {
			if fake.fail == "mount" {
				return nil, errors.New("fixture mount failure")
			}
			fake.rows = append(fake.rows, folders.LiveMount{ID: 100, Target: args[len(args)-1], Source: args[len(args)-2], FSType: args[2], Options: "rw"})
		}
		if args[0] == "systemctl" && fake.fail == "reload" {
			fake.fail = ""
			return nil, errors.New("fixture reload failure")
		}
		return nil, nil
	}
	s.attach = func(stage string, target *os.File, before func(uint64) error) (uint64, error) {
		if fake.fail == "attach" {
			return 0, errors.New("fixture attach failure")
		}
		if err := before(200); err != nil {
			return 0, err
		}
		row := fake.rows[0]
		row.ID = 200
		row.Target = target.Name()
		fake.rows = []folders.LiveMount{row}
		if fake.crash {
			panic("fixture interruption after attach")
		}
		return 200, nil
	}
	s.unmount = func(point string, expected folders.LiveMount) error {
		if fake.fail == "busy" {
			return errors.New("fixture busy mount")
		}
		for i, row := range fake.rows {
			if row.Target == point {
				if row != expected {
					return errors.New("wrong mount identity")
				}
				fake.rows = append(fake.rows[:i], fake.rows[i+1:]...)
				return nil
			}
		}
		return errors.New("mount disappeared")
	}
	return s, p, fake
}
func plannedFingerprint(t *testing.T, s *service, action string, p map[string]any) string {
	t.Helper()
	raw, err := s.plan(context.Background(), action, p, "member")
	if err != nil {
		t.Fatal(err)
	}
	var value struct{ Fingerprint string }
	json.Unmarshal(raw, &value)
	return value.Fingerprint
}
func TestMountLifecycleAndSecrets(t *testing.T) {
	s, p, fake := executionFixture(t)
	before, _ := os.ReadFile(s.fstab)
	fp := plannedFingerprint(t, s, "smb.mount", p)
	raw, err := s.execute(context.Background(), "smb.mount", p, "member", fp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.rows) != 1 || fake.rows[0].Target != param(p, "point") {
		t.Fatal(fake.rows)
	}
	conf, _ := os.ReadFile(s.fstab)
	commands, _ := json.Marshal(fake.commands)
	if strings.Contains(string(conf)+string(commands)+string(raw), "secret-value") {
		t.Fatal("secret escaped credential file")
	}
	if !strings.Contains(string(conf), "uid=1000,gid=1000") {
		t.Fatal(string(conf))
	}
	point := param(p, "point")
	u := map[string]any{"target": point}
	fp = plannedFingerprint(t, s, "smb.unmount", u)
	if _, err = s.execute(context.Background(), "smb.unmount", u, "member", fp, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.fstab)
	if string(after) != string(before) || len(fake.rows) != 0 {
		t.Fatal(string(after), fake.rows)
	}
	if _, err = os.Stat(filepath.Join(s.credentials, Key(point))); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	state, err := s.load(point)
	if err != nil || state != nil {
		t.Fatal(state, err)
	}
}
func TestFailedMountRollsBackOnlyOwnedState(t *testing.T) {
	for _, failure := range []string{"mount", "attach", "reload"} {
		t.Run(failure, func(t *testing.T) {
			s, p, fake := executionFixture(t)
			fake.fail = failure
			before, _ := os.ReadFile(s.fstab)
			fp := plannedFingerprint(t, s, "smb.mount", p)
			if _, err := s.execute(context.Background(), "smb.mount", p, "member", fp, nil); err == nil {
				t.Fatal("failure hidden")
			}
			after, _ := os.ReadFile(s.fstab)
			if string(after) != string(before) || len(fake.rows) != 0 {
				t.Fatal(string(after), fake.rows)
			}
			if _, err := os.Stat(filepath.Join(s.credentials, Key(param(p, "point")))); !os.IsNotExist(err) {
				t.Fatal(err)
			}
		})
	}
}
func TestBusyUnmountPreservesConfigurationAndCredentials(t *testing.T) {
	s, p, fake := executionFixture(t)
	fp := plannedFingerprint(t, s, "smb.mount", p)
	if _, err := s.execute(context.Background(), "smb.mount", p, "member", fp, nil); err != nil {
		t.Fatal(err)
	}
	conf, _ := os.ReadFile(s.fstab)
	credential := filepath.Join(s.credentials, Key(param(p, "point")))
	secret, _ := os.ReadFile(credential)
	u := map[string]any{"target": param(p, "point")}
	fp = plannedFingerprint(t, s, "smb.unmount", u)
	fake.fail = "busy"
	if _, err := s.execute(context.Background(), "smb.unmount", u, "member", fp, nil); err == nil {
		t.Fatal("busy ignored")
	}
	after, _ := os.ReadFile(s.fstab)
	kept, _ := os.ReadFile(credential)
	if string(after) != string(conf) || string(kept) != string(secret) || len(fake.rows) != 1 {
		t.Fatal("busy mount state changed")
	}
}
func TestInterruptedAttachCanBeExplicitlyUnmounted(t *testing.T) {
	s, p, fake := executionFixture(t)
	fake.crash = true
	fp := plannedFingerprint(t, s, "smb.mount", p)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("interruption not injected")
			}
		}()
		s.execute(context.Background(), "smb.mount", p, "member", fp, nil)
	}()
	state, err := s.load(param(p, "point"))
	if err != nil || state == nil || state.Phase != "attaching" || state.MountID != 200 {
		t.Fatal(state, err)
	}
	u := map[string]any{"target": param(p, "point")}
	fp = plannedFingerprint(t, s, "smb.unmount", u)
	if _, err = s.execute(context.Background(), "smb.unmount", u, "member", fp, nil); err != nil {
		t.Fatal(err)
	}
	if len(fake.rows) != 0 {
		t.Fatal(fake.rows)
	}
}

func TestOldConfiguredAbsentMountRemovesOnlyOwnedEntryAndCredential(t *testing.T) {
	s, p, _ := executionFixture(t)
	point := param(p, "point")
	before, _ := os.ReadFile(s.fstab)
	line := "//nas/share " + point + " cifs rw,credentials=" + filepath.Join(s.credentials, Key(point)) + " 0 0 " + marker(point) + "\n"
	os.WriteFile(s.fstab, append(before, []byte(line)...), 0600)
	os.Mkdir(s.credentials, 0700)
	credential := filepath.Join(s.credentials, Key(point))
	os.WriteFile(credential, []byte("username=member\npassword=old-secret\n"), 0600)
	params := map[string]any{"target": point}
	fp := plannedFingerprint(t, s, "smb.unmount", params)
	if _, err := s.execute(context.Background(), "smb.unmount", params, "member", fp, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.fstab)
	if string(after) != string(before) {
		t.Fatal(string(after))
	}
	if _, err := os.Stat(credential); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestForeignFstabAfterMountFailureIsPreserved(t *testing.T) {
	s, p, fake := executionFixture(t)
	original := s.attach
	s.attach = func(stage string, target *os.File, before func(uint64) error) (uint64, error) {
		id, err := original(stage, target, before)
		if err != nil {
			return id, err
		}
		if err = os.WriteFile(s.fstab, []byte("# foreign edit retained\n"), 0600); err != nil {
			t.Fatal(err)
		}
		return id, nil
	}
	fp := plannedFingerprint(t, s, "smb.mount", p)
	if _, err := s.execute(context.Background(), "smb.mount", p, "member", fp, nil); err == nil {
		t.Fatal("foreign edit accepted")
	}
	raw, _ := os.ReadFile(s.fstab)
	if string(raw) != "# foreign edit retained\n" || len(fake.rows) != 1 {
		t.Fatal(string(raw), fake.rows)
	}
	state, err := s.load(param(p, "point"))
	if err != nil || state == nil {
		t.Fatal(state, err)
	}
}
func TestBusyBlockerNamesServiceAndRecoveryIsReadOnly(t *testing.T) {
	s, p, fake := executionFixture(t)
	pid := filepath.Join(s.proc, "123")
	os.MkdirAll(pid, 0700)
	os.WriteFile(filepath.Join(pid, "comm"), []byte("worker\n"), 0600)
	os.WriteFile(filepath.Join(pid, "cgroup"), []byte("0::/system.slice/cloud-sync.service\n"), 0600)
	if got := s.busyDescription("123"); got != "123 (cloud-sync.service)" {
		t.Fatal(got)
	}
	result, err := s.recovery(param(p, "point"))
	if err != nil || result["mounted"] != false || len(fake.commands) != 0 {
		t.Fatal(result, err)
	}
	if _, err = os.Stat(s.root); !os.IsNotExist(err) {
		t.Fatal("read-only recovery created state", err)
	}
}

func TestCrashAfterStageMkdirRemainsRecoverable(t *testing.T) {
	s, p, _ := executionFixture(t)
	real := s.write
	s.write = func(path, text string, mode os.FileMode) error {
		if filepath.Ext(path) == ".json" && stringContains(text, `"stage":true`) {
			panic("power loss before stage ownership journal save")
		}
		return real(path, text, mode)
	}
	fp := plannedFingerprint(t, s, "smb.mount", p)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("no injected interruption")
			}
		}()
		s.execute(context.Background(), "smb.mount", p, "member", fp, nil)
	}()
	s.write = real
	u := map[string]any{"target": param(p, "point")}
	fp = plannedFingerprint(t, s, "smb.unmount", u)
	if _, err := s.execute(context.Background(), "smb.unmount", u, "member", fp, nil); err != nil {
		t.Fatal(err)
	}
	fp = plannedFingerprint(t, s, "smb.mount", p)
	if _, err := s.execute(context.Background(), "smb.mount", p, "member", fp, nil); err != nil {
		t.Fatalf("explicit recovery left next mount blocked: %v", err)
	}
}
func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestUnmountRetryReloadsRemovedFstab(t *testing.T) {
	s, p, fake := executionFixture(t)
	fp := plannedFingerprint(t, s, "smb.mount", p)
	if _, err := s.execute(context.Background(), "smb.mount", p, "member", fp, nil); err != nil {
		t.Fatal(err)
	}
	run := s.run
	failed := false
	s.run = func(ctx context.Context, args []string, o systemops.CommandOptions) ([]byte, error) {
		if args[0] == "systemctl" && !failed {
			failed = true
			return nil, errors.New("daemon reload unavailable")
		}
		return run(ctx, args, o)
	}
	u := map[string]any{"target": param(p, "point")}
	fp = plannedFingerprint(t, s, "smb.unmount", u)
	if _, err := s.execute(context.Background(), "smb.unmount", u, "member", fp, nil); err == nil {
		t.Fatal("failure not injected")
	}
	fake.commands = nil
	fp = plannedFingerprint(t, s, "smb.unmount", u)
	if _, err := s.execute(context.Background(), "smb.unmount", u, "member", fp, nil); err != nil {
		t.Fatal(err)
	}
	for _, args := range fake.commands {
		if args[0] == "systemctl" {
			return
		}
	}
	t.Fatal("retry deleted recovery state without retrying failed daemon-reload")
}

func TestStageIntentInterruptionAndForeignStagePreservation(t *testing.T) {
	for _, boundary := range []string{"intent", "created", "foreign"} {
		t.Run(boundary, func(t *testing.T) {
			s, p, _ := executionFixture(t)
			point := param(p, "point")
			stage := filepath.Join(s.root, Key(point)+".stage")
			original := s.write
			s.write = func(path, text string, mode os.FileMode) error {
				err := original(path, text, mode)
				if err == nil && strings.HasSuffix(path, ".json") && strings.Contains(text, `"stage":true`) {
					if boundary == "created" {
						if err := os.Mkdir(stage, 0700); err != nil {
							t.Fatal(err)
						}
					}
					panic("fixture after durable creation intent")
				}
				return err
			}
			if boundary == "foreign" {
				if err := os.MkdirAll(stage, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(stage, "keep"), []byte("foreign"), 0600); err != nil {
					t.Fatal(err)
				}
				s.write = original
			}
			fp := plannedFingerprint(t, s, "smb.mount", p)
			if boundary == "foreign" {
				if _, err := s.execute(context.Background(), "smb.mount", p, "member", fp, nil); err == nil {
					t.Fatal("foreign stage accepted")
				}
			} else {
				func() {
					defer func() {
						if recover() == nil {
							t.Fatal("no interruption")
						}
					}()
					s.execute(context.Background(), "smb.mount", p, "member", fp, nil)
				}()
			}
			s.write = original
			u := map[string]any{"target": point}
			fp = plannedFingerprint(t, s, "smb.unmount", u)
			if _, err := s.execute(context.Background(), "smb.unmount", u, "member", fp, nil); err != nil {
				t.Fatal(err)
			}
			if boundary == "foreign" {
				if raw, err := os.ReadFile(filepath.Join(stage, "keep")); err != nil || string(raw) != "foreign" {
					t.Fatal("foreign stage changed", err)
				}
			} else {
				if _, err := os.Lstat(stage); !os.IsNotExist(err) {
					t.Fatal("stage remains", err)
				}
				fp = plannedFingerprint(t, s, "smb.mount", p)
				if _, err := s.execute(context.Background(), "smb.mount", p, "member", fp, nil); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
