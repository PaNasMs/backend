package localmounts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops/storagequery"
)

func TestDisposablePartialEject(t *testing.T) {
	if os.Getenv("PANASMS_GO09_EJECT_FIXTURE") != "1" {
		t.Skip("requires isolated VM storage fixture")
	}
	read := func(path string) string {
		t.Helper()
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		return strings.TrimSpace(string(b))
	}
	if os.Geteuid() != 0 || os.Getenv("PANASMS_ACCEPTANCE_VM_UUID") == "" || !strings.EqualFold(read("/sys/class/dmi/id/product_uuid"), os.Getenv("PANASMS_ACCEPTANCE_VM_UUID")) || len(os.Getenv("PANASMS_GO09_NONCE")) != 32 || read("/fixture/nonce") != os.Getenv("PANASMS_GO09_NONCE") {
		t.Fatal("fixture guard failed")
	}
	if os.Getppid() != 1 || !strings.Contains(read("/proc/1/cmdline"), "/fixture/child.py\x00") {
		t.Fatal("requires the private fixture PID namespace")
	}
	var devices struct{ Disk, Partition string }
	if err := json.Unmarshal([]byte(read("/fixture/devices.json")), &devices); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile("^/dev/loop[0-9]+$").MatchString(devices.Disk) || devices.Partition != devices.Disk+"p1" {
		t.Fatal("unexpected fixture device")
	}
	s := defaultService()
	var err error
	s.sys, err = os.MkdirTemp("/fixture", "eject-sys-")
	if err != nil {
		t.Fatal(err)
	}
	class := filepath.Join(s.sys, filepath.Base(devices.Disk))
	if err := os.MkdirAll(filepath.Join(class, "device"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dev", "diskseq"} {
		if err := os.WriteFile(filepath.Join(class, name), []byte(read(filepath.Join("/sys/class/block", filepath.Base(devices.Disk), name))), 0600); err != nil {
			t.Fatal(err)
		}
	}
	signal := filepath.Join(class, "device/delete")
	if err := os.WriteFile(signal, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}
	realLoad := s.load
	s.load = func(ctx context.Context) (*storagequery.Preflight, error) {
		p, err := realLoad(ctx)
		if err != nil {
			return nil, err
		}
		if row := p.Inventory.Rows[devices.Disk]; row != nil && row["type"] == "loop" {
			row["type"] = "disk"
		} else {
			return nil, fmt.Errorf("fixture loop identity missing")
		}
		return p, nil
	}
	params := map[string]any{"target": devices.Disk}
	ctx := context.Background()
	busy := exec.Command("sleep", "120")
	busy.Dir = "/mnt/x"
	if err := busy.Start(); err != nil {
		t.Fatal(err)
	}
	_, err = s.prepare(ctx, "disk.eject", params, "admin")
	busy.Process.Kill()
	busy.Wait()
	if err == nil || !strings.Contains(err.Error(), fmt.Sprint(busy.Process.Pid)) {
		t.Fatalf("missing process refusal: %v", err)
	}
	plan, err := s.prepare(ctx, "disk.eject", params, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.selected) != 2 || plan.selected[0].Target != "/mnt/long-eject" || plan.selected[1].Target != "/mnt/x" {
		t.Fatalf("unexpected selected mounts %+v", plan.selected)
	}
	// Our descriptor is deliberately absent from the external process scan. The
	// second ordinary unmount must still honor the kernel's EBUSY.
	handle, err := os.Open("/mnt/x")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	_, err = s.execute(ctx, "disk.eject", params, "admin", plan.fingerprint, nil)
	if err == nil {
		t.Fatal("busy second mount reported success")
	}
	if err = handle.Close(); err != nil {
		t.Fatal(err)
	}
	state, _, err := readJournal(s.root, devices.Disk, 0)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || state.Phase != "pending" || len(state.Steps) != 2 || !state.Steps[0].Completed || state.Steps[1].Completed || read(signal) != "0" || read("/mnt/x/retained") != "preserved" {
		t.Fatalf("partial eject lost evidence: %+v", state)
	}
	plan, err = s.prepare(ctx, "disk.eject", params, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.selected) != 1 || plan.selected[0].Target != "/mnt/x" {
		t.Fatal("retry selected unrelated mount")
	}
	if _, err = s.execute(ctx, "disk.eject", params, "admin", plan.fingerprint, nil); err != nil {
		t.Fatal(err)
	}
	if read(signal) != "1" {
		t.Fatal("simulated control was not written")
	}
	state, _, err = readJournal(s.root, devices.Disk, 0)
	if err != nil || state == nil || state.Phase != "complete" {
		t.Fatalf("incomplete explicit retry: %+v %v", state, err)
	}
}
