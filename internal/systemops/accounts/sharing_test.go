package accounts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"panasms.local/backend/internal/systemops"
)

func sharingFixture(t *testing.T) *sharingService {
	t.Helper()
	s := defaultSharing()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	s.ownerUID = os.Geteuid()
	s.secureRoot = root
	s.activationTicket = filepath.Join(root, "activation-ticket")
	s.activationReceipt = filepath.Join(root, "activation-receipt")
	s.restoreGuard = filepath.Join(root, "restore-guard")
	s.packageVersion = func(context.Context) (string, error) { return "fixture-native", nil }
	s.authorizeNative = func(context.Context, string) error { return nil }
	s.authorizeTarget = func(context.Context, string) error { return nil }
	s.write = func(path, value string, mode os.FileMode) error {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(value), mode); err != nil {
			return err
		}
		return os.Chmod(path, mode)
	}
	s.state = filepath.Join(root, "state")
	s.smb = filepath.Join(root, "smb")
	s.exports = filepath.Join(root, "exports")
	s.legacy = filepath.Join(root, "legacy")
	s.journal = filepath.Join(root, "journal")
	s.lock = filepath.Join(root, "lock")
	s.mainConfig = filepath.Join(root, "smb.conf")
	s.installer = filepath.Join(root, "installer")
	s.vendor = filepath.Join(root, "vendor")
	s.passwd = filepath.Join(root, "passwd")
	s.group = filepath.Join(root, "group")
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		if slices.Equal(args, []string{"systemctl", "is-active", "smbd"}) {
			return []byte("active"), nil
		}
		return []byte(`{}`), nil
	}
	s.tool = func(string) bool { return true }
	s.user = func(name string) (passwdUser, error) {
		if name != "alice" && name != "bob" {
			return passwdUser{}, reject("User not found")
		}
		return passwdUser{Name: name, UID: 1000, GID: 1000, Dir: "/srv/data/homes/" + name}, nil
	}
	s.normal = func(passwdUser) error { return nil }
	s.groups = func() ([]groupEntry, error) { return []groupEntry{{Name: "family", GID: 1000}}, nil }
	s.revision = func(string) (string, error) { return "revision", nil }
	s.credentials = func(string) (sharingCredentials, error) {
		return sharingCredentials{UID: 1000, Revision: "revision", Shadow: ShadowState{PasswordStatus: "set", LastChange: today(), MaxDays: 99999, InactiveDays: -1, ExpiryDay: -1}}, nil
	}
	s.locate = func(_ context.Context, path string) (sharingMount, error) {
		if err := sharePathShape(path); err != nil {
			return sharingMount{}, err
		}
		return sharingMount{Target: "/srv/data", FSType: "ext4", UUID: "fixture-volume", Source: "/dev/fixture"}, nil
	}
	s.identity = func(string) ([]uint64, error) { return []uint64{7, 8}, nil }
	if err := os.WriteFile(s.mainConfig, []byte(sharingManaged), 0644); err != nil {
		t.Fatal(err)
	}
	return s
}
func sealLegacySharingFixture(t *testing.T, s *sharingService) {
	t.Helper()
	if exists, _ := sharingExists(s.legacy); exists {
		if err := os.Chmod(s.legacy, 0644); err != nil {
			t.Fatal(err)
		}
	}
	st, err := s.read()
	if err != nil {
		t.Fatal(err)
	}
	st.LegacyExportRevision, err = s.legacyRevision()
	if err != nil {
		t.Fatal(err)
	}
	if err = s.save(st); err != nil {
		t.Fatal(err)
	}
}

func sharingFolder() sharedFolder {
	return sharedFolder{Name: "Media", Path: "/srv/data/media", SMB: true, NFS: true, Readers: []string{"alice"}, Writers: []string{"@family"}, Clients: []string{"192.168.1.0/24"}, Volume: "fixture-volume", Mountpoint: "/srv/data"}
}
func sharingParams() map[string]any {
	return map[string]any{"name": "Media", "path": "/srv/data/media", "smb": true, "nfs": true, "readOnly": false, "clients": "192.168.1.42/24,192.168.1.0/24", "readers": []any{"alice"}, "writers": []any{"@family"}}
}
func saveSharingFixture(t *testing.T, s *sharingService, st sharingState) {
	t.Helper()
	if err := s.save(st); err != nil {
		t.Fatal(err)
	}
	smb, nfs := sharingConfig(st.Shares, false, false)
	if err := s.write(s.smb, smb, 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.write(s.exports, nfs, 0644); err != nil {
		t.Fatal(err)
	}
}
func sharingFingerprint(t *testing.T, s *sharingService, action string, p map[string]any) string {
	t.Helper()
	raw, err := s.plan(context.Background(), action, p)
	if err != nil {
		t.Fatal(err)
	}
	var plan struct{ Fingerprint string }
	if err = json.Unmarshal(raw, &plan); err != nil {
		t.Fatal(err)
	}
	return plan.Fingerprint
}
func TestSharingConfigPermissionsAndLegacyHooks(t *testing.T) {
	share := sharingFolder()
	smb, nfs := sharingConfig([]sharedFolder{share}, false, false)
	for _, value := range []string{"read only = yes", "write list = @family", "guest ok = no", "follow symlinks = no", "inherit permissions = no", "root preexec = /usr/lib/panasms/panasms-system-helper sharing check Media", "root preexec close = yes", "oplocks = no"} {
		if !strings.Contains(smb, value) {
			t.Errorf("missing %q", value)
		}
	}
	if strings.Contains(smb, "python") || !strings.Contains(nfs, "rw,sync,no_subtree_check,root_squash,mountpoint=/srv/data") {
		t.Fatal(smb, nfs)
	}
	old, _ := sharingConfig([]sharedFolder{share}, true, true)
	if !strings.Contains(old, "sharing.py --check Media") || !strings.Contains(old, "inherit permissions = yes") {
		t.Fatal(old)
	}
	share.SMB = false
	share.NFS = false
	a, b := sharingConfig([]sharedFolder{share}, false, false)
	if a != sharingHeader || b != sharingHeader {
		t.Fatal(a, b)
	}
}
func TestSharingNormalizeUnicodeIPsAndInjection(t *testing.T) {
	s := sharingFixture(t)
	p := sharingParams()
	p["name"] = "Документи"
	share, err := s.normalize(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(share.Clients, []string{"192.168.1.0/24"}) {
		t.Fatal(share.Clients)
	}
	for _, name := range []string{"global", "Homes", "name\npath=/", "foo]", "bad space", "%u", "a;cmd", "a/b", ".hidden", "-flag"} {
		q := sharingParams()
		q["name"] = name
		if _, err = s.normalize(context.Background(), q); err == nil {
			t.Error("accepted", name)
		}
	}
	for _, path := range []string{"/etc", "/srv/data/space dir", "/srv/data/a;cmd", "/srv/data/a#b", "/srv/data/%u", "/srv/data/../other"} {
		q := sharingParams()
		q["path"] = path
		if _, err = s.normalize(context.Background(), q); err == nil {
			t.Error("accepted path", path)
		}
	}
	for _, client := range []string{"*", "127.0.0.1(rw,no_root_squash)", "host.example", "fe80::1%eth0", "1.2.3.4/99"} {
		q := sharingParams()
		q["clients"] = client
		if _, err = s.normalize(context.Background(), q); err == nil {
			t.Error("accepted client", client)
		}
	}
	for input, want := range map[string]string{"192.0.2.8": "192.0.2.8/32", "2001:db8::7/64": "2001:db8::/64", "::1": "::1/128"} {
		got, err := sharingNetwork(input)
		if err != nil || got != want {
			t.Fatal(input, got, err)
		}
	}
	q := sharingParams()
	q["smb"] = "true"
	if _, err = s.normalize(context.Background(), q); err == nil {
		t.Fatal("string protocol accepted")
	}
}
func TestSharingPlansReadOnlyAndRevalidateUnderLock(t *testing.T) {
	s := sharingFixture(t)
	p := sharingParams()
	fp := sharingFingerprint(t, s, "share.save", p)
	for _, path := range []string{s.state, s.smb, s.exports, s.journal, s.lock} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("plan wrote", path, err)
		}
	}
	s.identity = func(string) ([]uint64, error) { return []uint64{7, 9}, nil }
	if _, err := s.execute(context.Background(), "share.save", p, fp, nil); err == nil || !strings.Contains(err.Error(), "State has changed") {
		t.Fatal(err)
	}
	if _, err := os.Lstat(s.journal); !os.IsNotExist(err) {
		t.Fatal("journal created before consent revalidation")
	}
	unlock, err := s.locked()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err = s.locked(); err == nil {
		t.Fatal("lock contention accepted")
	}
}
func TestSharingTransactionFailureAndRecovery(t *testing.T) {
	for _, failRollback := range []bool{false, true} {
		t.Run(pythonBool(failRollback), func(t *testing.T) {
			s := sharingFixture(t)
			old := sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}}
			saveSharingFixture(t, s, old)
			real := s.run
			failures := 1
			if failRollback {
				failures = 2
			}
			s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
				if slices.Equal(args, []string{"smbcontrol", "all", "reload-config"}) && failures > 0 {
					failures--
					return nil, errors.New("fixture restart failure")
				}
				return real(ctx, args, opt)
			}
			err := s.apply(context.Background(), sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}, nil)
			want := "previous configuration restored"
			if failRollback {
				want = "rollback needs recovery"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatal(err)
			}
			exists, _ := sharingExists(s.journal)
			if exists != failRollback {
				t.Fatal("journal", exists)
			}
			st, err := s.read()
			if err != nil || len(st.Shares) != 0 {
				t.Fatal(st, err)
			}
			if err = s.recover(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			if err = s.recover(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestSharingDeathAtEveryDurableWrite(t *testing.T) {
	for _, cut := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+cut)), func(t *testing.T) {
			s := sharingFixture(t)
			old := sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}}
			saveSharingFixture(t, s, old)
			real := s.write
			writes := 0
			s.write = func(path, value string, mode os.FileMode) error {
				if err := real(path, value, mode); err != nil {
					return err
				}
				writes++
				if writes == cut {
					panic("fixture process death")
				}
				return nil
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Error("death point not reached")
					}
				}()
				_ = s.apply(context.Background(), sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}, nil)
			}()
			s.write = real
			if err := s.recover(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			if err := s.recover(context.Background(), nil); err != nil {
				t.Fatal(err)
			}
			st, err := s.read()
			if err != nil || !reflect.DeepEqual(st, old) {
				t.Fatal(st, err)
			}
		})
	}
}
func TestSharingLegacyRepublishAndExternalEditPreservation(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		s := sharingFixture(t)
		st := sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}
		saveSharingFixture(t, s, st)
		smb, nfs := sharingConfig(st.Shares, true, legacy)
		os.WriteFile(s.smb, []byte(smb), 0644)
		os.WriteFile(s.exports, []byte(nfs), 0644)
		if err := s.republish(context.Background()); err != nil {
			t.Fatal(err)
		}
		changed, err := s.drift(st)
		if err != nil || changed {
			t.Fatal(changed, err)
		}
		text, _ := sharingText(s.smb)
		if strings.Contains(text, "python") {
			t.Fatal(text)
		}
		os.WriteFile(s.smb, []byte(smb+"# external edit\n"), 0644)
		if err = s.republish(context.Background()); err != nil {
			t.Fatal(err)
		}
		text, _ = sharingText(s.smb)
		if text != smb+"# external edit\n" {
			t.Fatal("external edit overwritten")
		}
	}
	s := sharingFixture(t)
	st := sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}
	s.save(st)
	os.WriteFile(s.smb, []byte(sharingHeader), 0644)
	if err := s.republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	changed, err := s.drift(st)
	if err != nil || changed {
		t.Fatal(changed, err)
	}
}
func TestSharingMissingMountNeverPublishesAndCheckRejectsReplacement(t *testing.T) {
	s := sharingFixture(t)
	s.locate = func(context.Context, string) (sharingMount, error) { return sharingMount{}, reject("not mounted") }
	if err := s.apply(context.Background(), sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}, nil); err == nil {
		t.Fatal("missing mount published")
	}
	if exists, _ := sharingExists(s.journal); exists {
		t.Fatal("journal before validation")
	}
	s.locate = func(context.Context, string) (sharingMount, error) {
		return sharingMount{Target: "/srv/data", UUID: "replacement"}, nil
	}
	if err := s.check(context.Background(), sharingFolder()); err == nil {
		t.Fatal("replacement accepted")
	}
}
func TestSharingMalformedRecoveryJournalNeverWrites(t *testing.T) {
	s := sharingFixture(t)
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}})
	before, _ := os.ReadFile(s.state)
	for _, raw := range []string{`{}`, `{"/etc/passwd":"replacement"}`, `{"bad":[]}`} {
		os.WriteFile(s.journal, []byte(raw), 0600)
		if err := s.recover(context.Background(), nil); err == nil {
			t.Fatal("invalid journal accepted")
		}
		after, _ := os.ReadFile(s.state)
		if !bytes.Equal(before, after) {
			t.Fatal("invalid recovery changed state")
		}
	}
}
func TestSharingRemoveOnlySelectedAndPreserveDefinitionsOnUninstall(t *testing.T) {
	s := sharingFixture(t)
	first := sharingFolder()
	second := first
	second.Name = "Elsewhere"
	second.Path = "/srv/data/elsewhere"
	st := sharingState{Shares: []sharedFolder{first, second}, Accounts: map[string]*sharedAccount{}}
	saveSharingFixture(t, s, st)
	removed, err := s.removeShares(context.Background(), []string{"Media", "missing"})
	if err != nil || len(removed) != 1 {
		t.Fatal(removed, err)
	}
	state, err := s.read()
	if err != nil || len(state.Shares) != 1 || state.Shares[0].Name != "Elsewhere" {
		t.Fatal(state, err)
	}
	if err = s.cli(context.Background(), []string{"remove"}, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	state, err = s.read()
	if err != nil || len(state.Shares) != 1 {
		t.Fatal(state, err)
	}
}
func TestSharingPasswordOnlyStdinAndRevisionNeverReturned(t *testing.T) {
	s := sharingFixture(t)
	uid := 1000
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{"alice": {UID: &uid, Enabled: true, Status: "pending"}}})
	secret := "fixture-only-password"
	inputs := []string{}
	real := s.run
	s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), secret) {
			t.Fatal("password in argv")
		}
		if args[0] == "smbpasswd" && slices.Contains(args, "-a") {
			inputs = append(inputs, string(opt.Input))
		}
		return real(ctx, args, opt)
	}
	if _, err := s.dependency(context.Background(), "sync-password", "alice", secret); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inputs, []string{secret + "\n" + secret + "\n"}) {
		t.Fatal("stdin contract", len(inputs))
	}
	raw, _ := os.ReadFile(s.state)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("password persisted")
	}
	for _, query := range []func() ([]byte, error){func() ([]byte, error) { return s.accountStatus("alice") }, func() ([]byte, error) { return s.query(context.Background()) }} {
		data, err := query()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("passwordRevision")) || bytes.Contains(data, []byte("revision")) || bytes.Contains(data, []byte(secret)) {
			t.Fatal("credential evidence exposed", string(data))
		}
	}
	s.revision = func(string) (string, error) { return "changed", nil }
	status, err := s.accountStatus("alice")
	if err != nil || !bytes.Contains(status, []byte(`"pending"`)) {
		t.Fatal(string(status), err)
	}
}
func TestSharingSyncFailureAndReusedUID(t *testing.T) {
	s := sharingFixture(t)
	uid := 1001
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{"alice": {UID: &uid, Enabled: true}}})
	calls := 0
	s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		calls++
		return nil, errors.New("never expose tool error fixture-only-password")
	}
	if _, err := s.dependency(context.Background(), "sync-password", "alice", "fixture-only-password"); err != nil || calls != 0 {
		t.Fatal(err, calls)
	}
	uid = 1000
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{"alice": {UID: &uid, Enabled: true}}})
	if _, err := s.dependency(context.Background(), "sync-password", "alice", "fixture-only-password"); err == nil || strings.Contains(err.Error(), "fixture-only-password") {
		t.Fatal(err)
	}
	st, err := s.read()
	if err != nil || st.Accounts["alice"].Status != "error" {
		t.Fatal(st, err)
	}
}
func TestSharingReconcileLockExpiryInactiveAndPasswordChange(t *testing.T) {
	for _, cause := range []string{"uid", "policy", "locked", "expired", "inactive", "changed", "removed"} {
		t.Run(cause, func(t *testing.T) {
			s := sharingFixture(t)
			uid := 1000
			saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{"alice": {UID: &uid, Enabled: true, Status: "ready", PasswordRevision: "revision"}}})
			creds, _ := s.credentials("alice")
			s.credentials = func(string) (sharingCredentials, error) {
				switch cause {
				case "uid":
					creds.UID++
				case "policy":
					creds.Disabled = true
				case "locked":
					creds.Shadow.PasswordStatus = "locked"
				case "expired":
					creds.Shadow.ExpiryDay = today()
				case "inactive":
					creds.Shadow.LastChange = 1
					creds.Shadow.MaxDays = 1
					creds.Shadow.InactiveDays = 1
				case "changed":
					creds.Revision = "new"
				case "removed":
					return creds, errors.New("missing")
				}
				return creds, nil
			}
			disabled := false
			real := s.run
			s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
				if args[0] == "smbpasswd" && slices.Contains(args, "-d") {
					disabled = true
				}
				return real(ctx, args, opt)
			}
			if err := s.reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			st, err := s.read()
			want := "disabled"
			if cause == "changed" {
				want = "pending"
			}
			if err != nil || !disabled || st.Accounts["alice"].Status != want {
				t.Fatal(disabled, st, err)
			}
		})
	}
}
func TestSharingReconcileContinuesAfterDisableFailure(t *testing.T) {
	s := sharingFixture(t)
	uid := 1000
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{
		"alice": {UID: &uid, Enabled: true, Status: "ready"},
		"bob":   {UID: &uid, Enabled: true, Status: "ready"},
	}})
	creds, _ := s.credentials("alice")
	creds.Shadow.PasswordStatus = "locked"
	s.credentials = func(string) (sharingCredentials, error) { return creds, nil }
	seen := map[string]bool{}
	real := s.run
	s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
		if args[0] == "smbpasswd" && slices.Contains(args, "-d") {
			user := args[len(args)-1]
			seen[user] = true
			if user == "alice" {
				return nil, errors.New("fixture disable failure")
			}
		}
		return real(ctx, args, opt)
	}
	if err := s.reconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "fixture disable failure") {
		t.Fatal(err)
	}
	st, err := s.read()
	if err != nil || !seen["alice"] || !seen["bob"] || st.Accounts["alice"].Status != "ready" || st.Accounts["bob"].Status != "disabled" {
		t.Fatal(st, seen, err)
	}
}

func TestSharingReconcileRetriesFailedSyncCleanupWithUnchangedRevision(t *testing.T) {
	s := sharingFixture(t)
	uid := 1000
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{
		"alice": {UID: &uid, Enabled: true, Status: "ready", PasswordRevision: "revision"},
	}})
	real := s.run
	disables := 0
	s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
		if args[0] == "smbpasswd" {
			if slices.Contains(args, "-a") {
				return nil, errors.New("fixture synchronization failure")
			}
			if slices.Contains(args, "-d") {
				disables++
				if disables == 1 {
					return nil, errors.New("fixture transient disable failure")
				}
			}
		}
		return real(ctx, args, opt)
	}
	if err := s.syncPassword(context.Background(), "alice", "fixture-only-password"); err == nil {
		t.Fatal("failed synchronization accepted")
	}
	if err := s.reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, err := s.read()
	if err != nil || disables != 2 || st.Accounts["alice"].Status != "error" || st.Accounts["alice"].PasswordRevision != "revision" {
		t.Fatal(st, disables, err)
	}
}

func TestSharingDisconnectOnlySelectedUserAndNotMainProcess(t *testing.T) {
	s := sharingFixture(t)
	pids := []string{}
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		switch args[0] {
		case "systemctl":
			if args[1] == "is-active" {
				return []byte("active"), nil
			}
			return []byte("10"), nil
		case "smbstatus":
			return []byte(`{"sessions":{"one":{"username":"alice","server_id":{"pid":21}},"two":{"username":"bob","server_id":{"pid":22}},"main":{"username":"alice","server_id":{"pid":10}},"duplicate":{"username":"alice","server_id":{"pid":21}},"invalid":{"username":"alice","server_id":{"pid":"bad"}}}}`), nil
		case "smbcontrol":
			pids = append(pids, args[1])
		}
		return nil, nil
	}
	// Samba emits numeric PIDs; malformed records must not signal any process.
	if err := s.disconnect(context.Background(), "alice", nil); err == nil {
		t.Fatal("malformed PID accepted")
	}
	if len(pids) != 0 {
		t.Fatal(pids)
	}
}
func TestSharingLegacyNFSRollbackAndPlanIdentity(t *testing.T) {
	s := sharingFixture(t)
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}})
	os.WriteFile(s.legacy, []byte("/srv/data/keep 192.0.2.1(ro,sync,no_subtree_check,root_squash)\n"), 0644)
	sealLegacySharingFixture(t, s)
	p := map[string]any{"target": "/srv/data/new", "clients": "127.0.0.1/32", "readOnly": false}
	fp := sharingFingerprint(t, s, "nfs.export", p)
	real := s.run
	failed := false
	s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
		if slices.Equal(args, []string{"exportfs", "-ra"}) && !failed {
			failed = true
			return nil, errors.New("invalid export")
		}
		return real(ctx, args, opt)
	}
	if _, err := s.execute(context.Background(), "nfs.export", p, fp, nil); err == nil || !strings.Contains(err.Error(), "previous configuration restored") {
		t.Fatal(err)
	}
	text, _ := sharingText(s.legacy)
	if strings.Contains(text, "/srv/data/new") {
		t.Fatal(text)
	}
	fp = sharingFingerprint(t, s, "nfs.export", p)
	if _, err := s.execute(context.Background(), "nfs.export", p, fp, nil); err != nil {
		t.Fatal(err)
	}
	text, _ = sharingText(s.legacy)
	if !strings.Contains(text, "root_squash") || strings.Contains(text, "no_root_squash") {
		t.Fatal(text)
	}
	rows, err := s.nfsEntries()
	if err != nil || len(rows) != 2 || !rows[0].ReadOnly || rows[1].ReadOnly {
		t.Fatal(rows, err)
	}
}
func TestSharingInstallerPreservesExternalConfigAndRestoresOnlyOwned(t *testing.T) {
	s := sharingFixture(t)
	os.WriteFile(s.mainConfig, []byte("custom [global]\n"), 0644)
	if err := s.install(context.Background()); err != nil {
		t.Fatal(err)
	}
	text, _ := sharingText(s.mainConfig)
	if text != "custom [global]\n" {
		t.Fatal(text)
	}
	s = sharingFixture(t)
	os.WriteFile(s.vendor, []byte("vendor\n"), 0644)
	os.WriteFile(s.mainConfig, []byte("vendor\n"), 0644)
	if err := s.install(context.Background()); err != nil {
		t.Fatal(err)
	}
	text, _ = sharingText(s.mainConfig)
	if text != sharingManaged {
		t.Fatal(text)
	}
	os.WriteFile(s.mainConfig, []byte(sharingManaged+"# edit\n"), 0644)
	if err := s.removeInstallation(); err != nil {
		t.Fatal(err)
	}
	text, _ = sharingText(s.mainConfig)
	if text != sharingManaged+"# edit\n" {
		t.Fatal("external edit discarded")
	}
}

func TestSharingWriterReaderInvariantAndMalformedOldState(t *testing.T) {
	s := sharingFixture(t)
	st := sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}
	st.Shares[0].Mountpoint = "/srv"
	s.locate = func(context.Context, string) (sharingMount, error) {
		return sharingMount{Target: "/srv", UUID: "fixture-volume"}, nil
	}
	if err := s.apply(context.Background(), st, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.read(); err != nil {
		t.Fatal("writer produced unreadable state", err)
	}
	malformed := st
	malformed.Shares = append([]sharedFolder{}, st.Shares...)
	malformed.Shares[0].Name = "global"
	if err := s.apply(context.Background(), malformed, nil); err == nil {
		t.Fatal("invalid initial state committed")
	}
	if exists, _ := sharingExists(s.journal); exists {
		t.Fatal("journal created for invalid state")
	}
	old := map[string]string{s.state: `{"shares":null,"accounts":{}}`, s.smb: "legacy", s.exports: "legacy"}
	raw, _ := json.Marshal(old)
	os.WriteFile(s.journal, raw, 0600)
	before, _ := os.ReadFile(s.state)
	if err := s.recover(context.Background(), nil); err == nil {
		t.Fatal("invalid old state restored")
	}
	after, _ := os.ReadFile(s.state)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid journal wrote before validation")
	}
}

func TestSharingRecoveryInspectionDoesNotReadCredentialsOrCallServices(t *testing.T) {
	s := sharingFixture(t)
	uid := 1000
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{"alice": {UID: &uid, Enabled: true, PasswordRevision: "hidden-revision"}}})
	s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
		t.Fatal("recovery inspection ran a tool")
		return nil, nil
	}
	s.credentials = func(string) (sharingCredentials, error) {
		t.Fatal("recovery inspected credentials")
		return sharingCredentials{}, nil
	}
	raw, err := s.recoveryView()
	if err != nil || bytes.Contains(raw, []byte("hidden-revision")) {
		t.Fatal(string(raw), err)
	}
}

func TestSharingOptionalClientsAndAccessListInputParity(t *testing.T) {
	s := sharingFixture(t)
	p := sharingParams()
	p["nfs"] = false
	delete(p, "clients")
	if _, err := s.normalize(context.Background(), p); err != nil {
		t.Fatal("missing clients rejected for SMB only", err)
	}
	p["clients"] = nil
	if _, err := s.normalize(context.Background(), p); err == nil {
		t.Fatal("null clients accepted")
	}
	p = sharingParams()
	p["readers"] = nil
	if _, err := s.normalize(context.Background(), p); err == nil {
		t.Fatal("null access list accepted")
	}
	p["readers"] = []any{123}
	if _, err := s.normalize(context.Background(), p); err == nil || err.Error() != "Invalid access entry" {
		t.Fatal(err)
	}
	values := []any{}
	for range 129 {
		values = append(values, "alice")
	}
	p["readers"] = values
	if _, err := s.normalize(context.Background(), p); err == nil {
		t.Fatal("oversized duplicate list accepted")
	}
}

func TestSharingDowngradeRestoresReleasedHookAndUpgradeRemigrates(t *testing.T) {
	s := sharingFixture(t)
	st := sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}
	saveSharingFixture(t, s, st)
	sealLegacySharingFixture(t, s)
	if err := s.cli(context.Background(), []string{"prepare-downgrade"}, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	text, _ := sharingText(s.smb)
	old, _ := sharingConfig(st.Shares, true, false)
	if text != old || strings.Contains(text, "system-helper sharing check") {
		t.Fatal(text)
	}
	if err := s.republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	changed, err := s.drift(st)
	if err != nil || changed {
		t.Fatal(changed, err)
	}
}
func TestSharingDowngradeRefusesJournalUntilExplicitRecoveryAndPreservesForeignEdit(t *testing.T) {
	s := sharingFixture(t)
	st := sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}
	saveSharingFixture(t, s, st)
	previous := "/srv/data/legacy 127.0.0.1(ro,sync,no_subtree_check,root_squash)\n"
	os.WriteFile(s.legacy, []byte(previous), 0644)
	sealLegacySharingFixture(t, s)
	if err := s.begin(true); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(s.legacy, []byte("changed"), 0644)
	if err := s.prepareDowngrade(context.Background()); err == nil || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatal(err)
	}
	if exists, _ := sharingExists(s.journal); !exists {
		t.Fatal("pending journal lost before compatible target veto")
	}
	if err := s.recover(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.prepareDowngrade(context.Background()); err != nil {
		t.Fatal(err)
	}
	text, _ := sharingText(s.legacy)
	if text != previous {
		t.Fatal("new journal not recovered before old package", text)
	}
	if exists, _ := sharingExists(s.journal); exists {
		t.Fatal("journal left for old reader")
	}
	if err := s.republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	text, _ = sharingText(s.smb)
	os.WriteFile(s.smb, []byte(text+"# foreign edit\n"), 0644)
	if err := s.prepareDowngrade(context.Background()); err == nil {
		t.Fatal("foreign native hook overwritten")
	}
	after, _ := sharingText(s.smb)
	if after != text+"# foreign edit\n" {
		t.Fatal(after)
	}
}

func TestSharingDisconnectLeavesOtherUsersAndServerRunning(t *testing.T) {
	s := sharingFixture(t)
	pids := []string{}
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		switch args[0] {
		case "systemctl":
			if args[1] == "is-active" {
				return []byte("active"), nil
			}
			return []byte("10"), nil
		case "smbstatus":
			return []byte(`{"sessions":{"a":{"username":"alice","server_id":{"pid":21}},"b":{"username":"bob","server_id":{"pid":22}},"main":{"username":"alice","server_id":{"pid":10}},"duplicate":{"username":"alice","server_id":{"pid":21}},"init":{"username":"alice","server_id":{"pid":1}}}}`), nil
		case "smbcontrol":
			pids = append(pids, args[1])
		}
		return nil, nil
	}
	if err := s.disconnect(context.Background(), "alice", nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pids, []string{"21"}) {
		t.Fatal("wrong session targets", pids)
	}
}

func TestSharingFailedSyncRevokesStalePasswordImmediately(t *testing.T) {
	s := sharingFixture(t)
	uid := 1000
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{"alice": {UID: &uid, Enabled: true, Status: "ready", PasswordRevision: "old"}}})
	disabled := false
	s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
		if args[0] == "smbpasswd" && slices.Contains(args, "-a") {
			return nil, errors.New("fixture failure")
		}
		if args[0] == "smbpasswd" && slices.Contains(args, "-d") {
			disabled = true
		}
		return []byte("inactive"), nil
	}
	if _, err := s.dependency(context.Background(), "sync-password", "alice", "fixture-password"); err == nil {
		t.Fatal("failed synchronization succeeded")
	}
	st, err := s.read()
	if err != nil || !disabled || st.Accounts["alice"].Status != "error" {
		t.Fatal(disabled, st, err)
	}
}
func TestSharingStartupRecoveryWaitsForLockAndRespectsCancellation(t *testing.T) {
	s := sharingFixture(t)
	unlock, err := s.locked()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err = s.lockedContext(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.cli(context.Background(), []string{"recover"}, nil, io.Discard) }()
	select {
	case err := <-done:
		t.Fatal("startup did not wait", err)
	case <-time.After(40 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("startup did not acquire released lock")
	}
}

func TestSharingOfflineLegacyExportCanBeRemovedAndBlocksNoUnrelatedWork(t *testing.T) {
	s := sharingFixture(t)
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}})
	os.WriteFile(s.legacy, []byte("/srv/offline/data 192.0.2.1(rw,sync,no_subtree_check,root_squash)\n"), 0644)
	sealLegacySharingFixture(t, s)
	old := s.locate
	s.locate = func(ctx context.Context, path string) (sharingMount, error) {
		if strings.HasPrefix(path, "/srv/offline") {
			return sharingMount{}, errors.New("missing volume")
		}
		return old(ctx, path)
	}
	p := map[string]any{"target": "/srv/offline/data"}
	fp := sharingFingerprint(t, s, "nfs.export-remove", p)
	if _, err := s.execute(context.Background(), "nfs.export-remove", p, fp, nil); err != nil {
		t.Fatal(err)
	}
	rows, err := s.nfsEntries()
	if err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
	if exists, _ := sharingExists(s.journal); exists {
		t.Fatal("removal journal retained")
	}
}
func TestSharingCannotCreateDuplicateManagedNFSPolicy(t *testing.T) {
	s := sharingFixture(t)
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}})
	if _, err := s.plan(context.Background(), "nfs.export", map[string]any{"target": sharingFolder().Path, "clients": "127.0.0.1", "readOnly": false}); err == nil || !strings.Contains(err.Error(), "already managed") {
		t.Fatal(err)
	}
}
func TestSharingRemoveSelectedWhileUnchangedOtherVolumeIsOffline(t *testing.T) {
	s := sharingFixture(t)
	a := sharingFolder()
	b := a
	b.Name = "Offline"
	b.Path = "/srv/offline/data"
	b.Mountpoint = "/srv/offline"
	saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{a, b}, Accounts: map[string]*sharedAccount{}})
	s.locate = func(context.Context, string) (sharingMount, error) {
		return sharingMount{}, errors.New("volume offline")
	}
	removed, err := s.removeShares(context.Background(), []string{a.Name})
	if err != nil || len(removed) != 1 {
		t.Fatal(removed, err)
	}
	st, err := s.read()
	if err != nil || len(st.Shares) != 1 || st.Shares[0].Name != "Offline" {
		t.Fatal(st, err)
	}
	if exists, _ := sharingExists(s.journal); exists {
		t.Fatal("unrelated offline share trapped recovery")
	}
}

func TestSharingRetainedMountedShareStillValidatesIdentityAndLinks(t *testing.T) {
	for _, cause := range []string{"volume", "link", "inventory"} {
		t.Run(cause, func(t *testing.T) {
			s := sharingFixture(t)
			saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}})
			s.locate = func(context.Context, string) (sharingMount, error) {
				if cause == "volume" {
					return sharingMount{Target: "/srv/data", UUID: "replaced-volume"}, nil
				}
				return sharingMount{}, reject("Links in the mount path are not allowed")
			}
			real := s.run
			s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
				if slices.Equal(args, []string{"findmnt", "--json", "--list", "--output", "TARGET"}) {
					if cause == "inventory" {
						return nil, errors.New("fixture mount inventory unavailable")
					}
					return []byte(`{"filesystems":[{"target":"/srv/data"}]}`), nil
				}
				return real(ctx, args, opt)
			}
			before, _ := os.ReadFile(s.smb)
			if err := s.apply(context.Background(), sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}, nil); err == nil {
				t.Fatal("retained mounted share bypassed identity/link validation")
			}
			after, _ := os.ReadFile(s.smb)
			if !bytes.Equal(before, after) {
				t.Fatal("configuration changed before refusing mounted share")
			}
			if exists, _ := sharingExists(s.journal); exists {
				t.Fatal("journal created before retained-share validation")
			}
		})
	}
}

func TestSharingAccountCallbacksWaitAndReauthorize(t *testing.T) {
	for _, scenario := range []string{"released", "cancelled", "guard-changed"} {
		t.Run(scenario, func(t *testing.T) {
			s := sharingFixture(t)
			uid := 1000
			saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{"alice": {UID: &uid, Enabled: true, Status: "pending"}}})
			s.authorizeNative = func(context.Context, string) error {
				if _, err := os.Stat(s.restoreGuard); err == nil {
					return errors.New("fixture restore guard")
				}
				return nil
			}
			unlock, err := s.locked()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if unlock != nil {
					unlock()
				}
			}()
			called := make(chan struct{}, 20)
			original := s.run
			s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
				called <- struct{}{}
				return original(ctx, args, opt)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := s.dependency(ctx, "sync-password", "alice", "fixture-password"); done <- err }()
			select {
			case err := <-done:
				t.Fatal("callback did not wait", err)
			case <-time.After(40 * time.Millisecond):
			}
			select {
			case <-called:
				t.Fatal("commands before lock acquisition")
			default:
			}
			if scenario == "cancelled" {
				cancel()
			}
			if scenario == "guard-changed" {
				if err := os.WriteFile(s.restoreGuard, []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "cancelled" {
				unlock()
				unlock = nil
			}
			select {
			case err := <-done:
				if scenario == "released" && err != nil {
					t.Fatal(err)
				}
				if scenario == "cancelled" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if scenario == "guard-changed" && (err == nil || !strings.Contains(err.Error(), "fixture restore guard")) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("callback did not finish")
			}
			if scenario != "released" {
				select {
				case <-called:
					t.Fatal("denied callback ran commands")
				default:
				}
			}
		})
	}
}

func TestSharingLegacyNFSMatchesPathFieldForRemoveAndReplace(t *testing.T) {
	for _, prefix := range []string{"", "  ", "\t"} {
		for _, separator := range []string{" ", "\t"} {
			for _, action := range []string{"nfs.export-remove", "nfs.export"} {
				t.Run(prefix+separator+action, func(t *testing.T) {
					s := sharingFixture(t)
					saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}})
					keep := "# retained comment\n/srv/data/legacy-other 192.0.2.1(ro,sync,no_subtree_check,root_squash)\n"
					if err := os.WriteFile(s.legacy, []byte(keep+prefix+"/srv/data/legacy"+separator+"127.0.0.1(ro,sync,no_subtree_check,root_squash)\n"), 0644); err != nil {
						t.Fatal(err)
					}
					sealLegacySharingFixture(t, s)
					p := map[string]any{"target": "/srv/data/legacy", "clients": "127.0.0.2/32", "readOnly": false}
					fp := sharingFingerprint(t, s, action, p)
					if _, err := s.execute(context.Background(), action, p, fp, nil); err != nil {
						t.Fatal(err)
					}
					text, err := sharingText(s.legacy)
					if err != nil || !strings.HasPrefix(text, keep) {
						t.Fatal(text, err)
					}
					rows, err := s.nfsEntries()
					if err != nil {
						t.Fatal(err)
					}
					count := 0
					for _, row := range rows {
						if row.Path == "/srv/data/legacy" {
							count++
							if action == "nfs.export" && (row.ReadOnly || !slices.Equal(row.Clients, []string{"127.0.0.2/32"})) {
								t.Fatal(row)
							}
						}
					}
					expected := 0
					if action == "nfs.export" {
						expected = 1
					}
					if count != expected {
						t.Fatal(rows)
					}
				})
			}
		}
	}
}
