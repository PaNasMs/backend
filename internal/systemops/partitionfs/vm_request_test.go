package partitionfs

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
)

// The source runner deliberately bypasses dispatch; authorization and packaged
// helper acceptance require separate tests.
func TestDisposableVMRequest(t *testing.T) {
	requestPath := os.Getenv("PANASMS_GO09_REQUEST")
	if requestPath == "" {
		t.Skip("requires the reviewed disposable VM namespace fixture")
	}
	uuid := strings.ToLower(os.Getenv("PANASMS_ACCEPTANCE_VM_UUID"))
	dmi, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if os.Geteuid() != 0 || uuid == "" || err != nil || strings.ToLower(strings.TrimSpace(string(dmi))) != uuid {
		t.Fatal("requires root in the designated disposable VM")
	}
	nonce := os.Getenv("PANASMS_GO09_NONCE")
	if len(nonce) != 32 {
		t.Fatal("missing private namespace nonce")
	}
	read := func(path string) []byte {
		t.Helper()
		if filepath.Dir(path) != "/fixture" {
			t.Fatal("request must be in private fixture directory")
		}
		for _, name := range []string{"/fixture", path} {
			info, e := os.Lstat(name)
			if e != nil {
				t.Fatal(e)
			}
			st := info.Sys().(*syscall.Stat_t)
			if st.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
				t.Fatal("unsafe private fixture input")
			}
			if name == path && (!info.Mode().IsRegular() || st.Nlink != 1 || info.Size() > 65536) {
				t.Fatal("invalid private fixture input")
			}
		}
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		return data
	}
	if string(read("/fixture/nonce")) != nonce {
		t.Fatal("private namespace nonce mismatch")
	}
	var devices struct {
		Disk      string `json:"disk"`
		Partition string `json:"partition"`
	}
	if err = systemops.Decode(read("/fixture/devices.json"), &devices); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^/dev/loop[0-9]+$`).MatchString(devices.Disk) {
		t.Fatal("fixture requires an owned loop device")
	}
	var req struct {
		Mode        string         `json:"mode"`
		Action      string         `json:"action"`
		Params      map[string]any `json:"params"`
		Fingerprint string         `json:"fingerprint"`
	}
	if err = systemops.Decode(read(requestPath), &req); err != nil {
		t.Fatal(err)
	}
	if !IsAction(req.Action) && req.Action != "storage.recover" {
		t.Fatal("action outside disposable storage scope")
	}
	target, _ := req.Params["target"].(string)
	if target != devices.Disk && !regexp.MustCompile("^"+regexp.QuoteMeta(devices.Disk)+`p[1-9][0-9]*$`).MatchString(target) {
		t.Fatal("target is not the fixture loop or its partition")
	}
	// No other block node may be reachable from this root.
	err = filepath.WalkDir("/dev", func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice == 0 {
			if path != devices.Disk && !regexp.MustCompile("^"+regexp.QuoteMeta(devices.Disk)+`p[1-9][0-9]*$`).MatchString(path) {
				return fmt.Errorf("unexpected block device in private root")
			}
			name := filepath.Base(path)
			raw, e := os.ReadFile(filepath.Join("/sys/class/block", name, "dev"))
			if os.IsNotExist(e) {
				return nil
			}
			if e != nil {
				return e
			}
			var major, minor uint64
			if _, e = fmt.Sscanf(strings.TrimSpace(string(raw)), "%d:%d", &major, &minor); e != nil {
				return e
			}
			st := info.Sys().(*syscall.Stat_t)
			if uint64(st.Rdev) != uint64(unix.Mkdev(uint32(major), uint32(minor))) {
				return fmt.Errorf("fixture block node identity mismatch")
			}
			if path != devices.Disk {
				resolved, e := filepath.EvalSymlinks(filepath.Join("/sys/class/block", name))
				if e != nil {
					return e
				}
				if filepath.Base(filepath.Dir(resolved)) != filepath.Base(devices.Disk) {
					return fmt.Errorf("fixture partition parent mismatch")
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var result json.RawMessage
	switch req.Mode {
	case "plan":
		if req.Action == "storage.recover" {
			result, err = storagebase.ConfigRecoveryPlan(ctx, req.Params)
		} else {
			result, err = Plan(ctx, req.Action, req.Params)
		}
	case "execute":
		if req.Action == "storage.recover" {
			result, err = storagebase.ConfigRecoveryExecute(ctx, req.Params, req.Fingerprint, nil)
		} else {
			result, err = Execute(ctx, req.Action, req.Params, req.Fingerprint, nil)
		}
	case "recover":
		result, err = Recovery(target)
	default:
		t.Fatal("unknown fixture mode")
	}
	output := map[string]any{"ok": err == nil, "data": result}
	if err != nil {
		output["error"] = err.Error()
	}
	encoded, e := json.Marshal(output)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println("PANASMS_GO09_RESULT=" + string(encoded))
}
