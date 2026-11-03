package modulelifecycle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const acceptanceRoot = "/var/lib/panasms-go14-acceptance"

func acceptanceGuard(t *testing.T) (lifecycle, []byte, string) {
	t.Helper()
	if os.Getenv("PANASMS_MODULE_VM_ACCEPTANCE") != "1" {
		t.Skip("requires exclusively owned, snapshot-backed disconnected VM200")
	}
	if os.Geteuid() != 0 {
		t.Fatal("acceptance requires isolated guest root")
	}
	raw, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil || strings.ToLower(strings.TrimSpace(string(raw))) != "c37154d3-9ce3-4440-bae7-507700ae8108" {
		t.Fatal("VM identity refused", err)
	}
	run := func(argv ...string) []byte {
		raw, err := systemops.Command(context.Background(), argv, systemops.CommandOptions{Timeout: 10 * time.Second, Accepted: []int{0, 1}})
		if err != nil {
			t.Fatal("guest guard failed", argv[0], err)
		}
		return raw
	}
	if kind := strings.TrimSpace(string(run("systemd-detect-virt", "--vm"))); kind != "kvm" && kind != "qemu" {
		t.Fatal("hypervisor refused")
	}
	var links []struct {
		Name  string   `json:"ifname"`
		Flags []string `json:"flags"`
	}
	if err := json.Unmarshal(run("ip", "-j", "link"), &links); err != nil {
		t.Fatal(err)
	}
	for _, link := range links {
		if link.Name != "lo" && contains(link.Flags, "LOWER_UP") {
			t.Fatal("connected guest refused")
		}
	}
	for _, version := range []string{"-4", "-6"} {
		var routes []json.RawMessage
		if err := json.Unmarshal(run("ip", version, "-j", "route"), &routes); err != nil || len(routes) != 0 {
			t.Fatal("guest routes refused", err)
		}
	}
	var mounted struct {
		Filesystems []json.RawMessage `json:"filesystems"`
	}
	raw = run("findmnt", "-J", "-t", "virtiofs,9p,nfs,nfs4,cifs,fuse.sshfs")
	if len(bytes.TrimSpace(raw)) > 0 {
		if err = json.Unmarshal(raw, &mounted); err != nil || len(mounted.Filesystems) != 0 {
			t.Fatal("external mounts refused", err)
		}
	}
	baseline := os.Getenv("PANASMS_MODULE_VM_BASELINE")
	if baseline == "" || strings.TrimSpace(string(run("dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", "panasms-prototype"))) != "installed "+baseline {
		t.Fatal("installed baseline refused")
	}
	updates, err := trustedDirectory("/var/lib/panasms-updates", 0)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err == nil {
		raw, err := readOwnedAt(updates, "state.json", 0, 1<<20)
		updates.Close()
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err == nil {
			var update struct {
				Phase string `json:"phase"`
			}
			if systemops.Decode(raw, &update) != nil || !contains([]string{"", "idle", "complete", "failed", "checked", "downloaded", "rolled-back"}, update.Phase) {
				t.Fatal("pending system update refused")
			}
		}
	}
	server := os.Getenv("PANASMS_MODULE_FIXTURE_SERVER")
	expected := os.Getenv("PANASMS_MODULE_FIXTURE_SERVER_SHA256")
	if !digestPattern.MatchString(expected) {
		t.Fatal("missing fixture server hash")
	}
	dir, err := trustedDirectory(filepath.Dir(server), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	raw, err = readOwnedAt(dir, filepath.Base(server), 0, maxArchive)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != expected {
		t.Fatal("fixture server hash refused")
	}
	s, err := installedLifecycle()
	if err != nil {
		t.Fatal(err)
	}
	s.root, s.keys, s.uploads = acceptanceRoot+"/modules", acceptanceRoot+"/keys", acceptanceRoot+"/uploads"
	return s, raw, baseline
}

func acceptanceBundle(t *testing.T, s lifecycle, server []byte, private ed25519.PrivateKey, version, behavior string) map[string]any {
	t.Helper()
	entries := map[string][]byte{"bundle.json": []byte(`{"root":"go14-app"}`)}
	for _, id := range []string{"go14-base", "go14-app"} {
		files := map[string][]byte{"ui/index.js": []byte("export default 'fixture';"), "bin/server": server, "backend/revision": []byte(behavior), "backend/version": []byte(version)}
		manifest := Manifest{"id": id, "version": version, "api": 1, "core": ">=0.2.0,<1.0.0", "architecture": "all", "title": "Lifecycle fixture", "service": "bin/server", "signer": "go14fixture"}
		if id == "go14-app" {
			manifest["dependencies"] = map[string]any{"go14-base": ">=1.0.0"}
		}
		digests := map[string]any{}
		for name, content := range files {
			hash := sha256.Sum256(content)
			digests[name] = hex.EncodeToString(hash[:])
			entries["modules/"+id+"/"+name] = content
		}
		manifest["files"] = digests
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		entries["modules/"+id+"/manifest.json"] = raw
		entries["modules/"+id+"/signature"] = ed25519.Sign(private, raw)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, name := range names(entries) {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	token := hex.EncodeToString(nonce[:])
	if err := os.WriteFile(filepath.Join(s.uploads, "go14actor-"+token+".zip"), archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return map[string]any{"upload": token}
}

func acceptanceExecute(t *testing.T, s lifecycle, action string, params map[string]any, authorize func() error) error {
	t.Helper()
	plan, err := s.prepare(context.Background(), action, params, "go14actor")
	if err != nil {
		return err
	}
	if plan.archive != nil {
		plan.archive.Close()
	}
	_, err = s.execute(context.Background(), action, params, "go14actor", plan.fingerprint, nil, authorize)
	return err
}

func acceptanceWait(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("fixture observation timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestIsolatedModuleLifecycleAcceptance(t *testing.T) {
	s, server, baseline := acceptanceGuard(t)
	if _, err := os.Lstat(acceptanceRoot); !os.IsNotExist(err) {
		t.Fatal("existing fixture state refused", err)
	}
	for _, id := range []string{"go14-base", "go14-app"} {
		if _, err := os.Lstat("/run/panasms-modules/" + id + ".sock"); !os.IsNotExist(err) {
			t.Fatal("existing fixture socket refused", err)
		}
		if _, err := os.Lstat(filepath.Join(s.units, unit(id))); !os.IsNotExist(err) {
			t.Fatal("existing fixture service refused", err)
		}
		out, err := s.run(context.Background(), []string{"systemctl", "show", "--property=LoadState", "--value", unit(id)}, systemops.CommandOptions{Accepted: []int{0, 4}, Timeout: 10 * time.Second})
		if err != nil || strings.TrimSpace(string(out)) != "not-found" {
			t.Fatal("loaded fixture service refused", err)
		}
	}
	if err := os.Mkdir(acceptanceRoot, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := os.Stat(acceptanceRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		current, err := os.Stat(acceptanceRoot)
		if err != nil || !os.SameFile(identity, current) {
			t.Error("fixture root changed; full owner snapshot restore required")
			return
		}
		if err := s.recovery().noMounts(acceptanceRoot); err != nil {
			t.Error("fixture mounts remain; full owner snapshot restore required")
			return
		}
		for _, id := range []string{"go14-app", "go14-base"} {
			state, err := s.run(context.Background(), []string{"systemctl", "show", "--property=LoadState", "--value", unit(id)}, systemops.CommandOptions{Accepted: []int{0, 4}, Timeout: 10 * time.Second})
			if err != nil {
				t.Error(err)
				return
			}
			if strings.TrimSpace(string(state)) == "not-found" {
				continue
			}
			if _, err := s.run(context.Background(), []string{"systemctl", "disable", "--now", unit(id)}, systemops.CommandOptions{Accepted: []int{0, 5}, Operation: true}); err != nil {
				t.Error("fixture service still active; preserving all files", err)
				return
			}
		}
		units, err := trustedDirectory(s.units, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer units.Close()
		for _, id := range []string{"go14-base", "go14-app"} {
			actual, err := snapshotAt(units, unit(id), 0)
			expected, _ := unitContent(s.root, Manifest{"id": id, "service": "bin/server"})
			if err != nil || actual.Exists && !bytes.Equal(actual.Data, expected) {
				t.Error("foreign fixture unit preserved", id, err)
				return
			}
			if err := restoreUnit(units, unit(id), fileSnapshot{}, 0); err != nil {
				t.Error(err)
				return
			}
		}
		if _, err := s.run(context.Background(), []string{"systemctl", "daemon-reload"}, systemops.CommandOptions{Operation: true}); err != nil {
			t.Error(err)
			return
		}
		sockets, err := trustedDirectory("/run/panasms-modules", 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer sockets.Close()
		for _, id := range []string{"go14-base", "go14-app"} {
			var stat unix.Stat_t
			err := unix.Fstatat(int(sockets.Fd()), id+".sock", &stat, unix.AT_SYMLINK_NOFOLLOW)
			if err == unix.ENOENT {
				continue
			}
			if err != nil || stat.Uid != 0 || stat.Nlink != 1 || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
				t.Error("foreign fixture socket preserved", err)
				return
			}
			if err = unix.Unlinkat(int(sockets.Fd()), id+".sock", 0); err != nil {
				t.Error(err)
				return
			}
		}
		if err = sockets.Sync(); err != nil {
			t.Error(err)
			return
		}
		if err := os.RemoveAll(acceptanceRoot); err != nil {
			t.Error(err)
		}
	}()
	for _, directory := range []string{s.root, s.keys, s.uploads, acceptanceRoot + "/data/go14-base", acceptanceRoot + "/data/go14-app"} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(s.root, 0755); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.keys, "go14fixture.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	data := acceptanceRoot + "/data/go14-app/retained"
	if err := os.WriteFile(data, []byte("retained module data"), 0600); err != nil {
		t.Fatal(err)
	}
	authorize := func() error { return nil }
	install := func(version, behavior string, check func() error) error {
		return acceptanceExecute(t, s, "module.install", acceptanceBundle(t, s, server, private, version, behavior), check)
	}
	if err := install("1.0.0", "healthy", authorize); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS real SDK services and dependency-ordered signed install")
	before, err := s.registry()
	if err != nil {
		t.Fatal(err)
	}
	flags := acceptanceRoot + "/data/go14-app"
	arm := func() {
		for _, name := range []string{"hold", "armed"} {
			if err := os.WriteFile(filepath.Join(flags, name), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	disarm := func() {
		for _, name := range []string{"armed", "hold"} {
			if err := os.Remove(filepath.Join(flags, name)); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
		acceptanceWait(t, func() bool {
			state, err := health(context.Background(), "go14-app")
			value, valid := integer(state["active"])
			return err == nil && valid && value == 0
		})
	}
	checks := 0
	err = install("1.1.0", "healthy", func() error {
		checks++
		if checks == 4 {
			arm()
			acceptanceWait(t, func() bool {
				state, err := health(context.Background(), "go14-app")
				value, valid := integer(state["active"])
				return err == nil && valid && value == 1
			})
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "Active requests or tasks") {
		t.Fatal("scheduled task did not block critical activation", err)
	}
	disarm()
	current, err := s.registry()
	if err != nil || !registryEqual(before, current) {
		t.Fatal("scheduler-winning abort changed registry", err)
	}
	if pending, err := s.loadTransaction(); err != nil || pending != nil {
		t.Fatal("staging-only abort retained a transaction", err)
	}
	t.Log("PASS SDK auto-retry acquires SH after idle check and prevents switching")
	checks = 0
	if err := install("1.1.0", "healthy", func() error {
		checks++
		if checks == 5 {
			arm()
			acceptanceWait(t, func() bool { _, err := os.Stat(filepath.Join(flags, "blocked")); return err == nil })
			disarm()
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS critical EX rejects SDK auto-retry before service replacement")
	acceptanceInterruptions(t, s, server, private)
	before, err = s.registry()
	if err != nil {
		t.Fatal(err)
	}
	if err := install("1.2.0", "fail-start", authorize); err == nil {
		t.Fatal("failed service start was accepted")
	}
	current, err = s.registry()
	if err != nil || !registryEqual(before, current) {
		t.Fatal("failed service start did not restore exact registry", err)
	}
	if pending, err := s.loadTransaction(); err != nil || pending != nil {
		t.Fatal("failed-start rollback incomplete", err)
	}
	t.Log("PASS actual failed service start rolls back code, units, registry and identity")
	if err := acceptanceExecute(t, s, "module.disable", map[string]any{"target": "go14-app"}, authorize); err != nil {
		t.Fatal(err)
	}
	if err := install("1.2.0", "healthy", authorize); err != nil {
		t.Fatal(err)
	}
	current, err = s.registry()
	if err != nil || current["go14-app"]["enabled"] != false || current["go14-app"]["installation"] != before["go14-app"]["installation"] {
		t.Fatal("disabled upgrade changed intent or identity", err)
	}
	if _, err := s.run(context.Background(), []string{"systemctl", "disable", "--now", unit("go14-base")}, systemops.CommandOptions{Operation: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if active, err := s.run(context.Background(), []string{"systemctl", "is-active", unit("go14-app")}, systemops.CommandOptions{Accepted: []int{0, 3, 4}}); err != nil || strings.TrimSpace(string(active)) != "inactive" {
		t.Fatal("reinstall resume started disabled module", err)
	}
	t.Log("PASS disabled update and reinstall resume preserve identity and intent")
	for _, id := range []string{"go14-app", "go14-base"} {
		if err := acceptanceExecute(t, s, "module.remove", map[string]any{"target": id}, authorize); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(s.root, id)); !os.IsNotExist(err) {
			t.Fatal("removed code remains", err)
		}
	}
	if raw, err := os.ReadFile(data); err != nil || string(raw) != "retained module data" {
		t.Fatal("module data not preserved", err)
	}
	t.Log("PASS removing code preserves module data")
	fmt.Printf("GO14_VM_ACCEPTANCE_PASS %s\n", baseline)
}
