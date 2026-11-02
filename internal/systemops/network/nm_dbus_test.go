package network

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"panasms.local/backend/internal/systemops"
)

type nmFixture struct {
	mu               sync.Mutex
	props            map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	profiles         map[dbus.ObjectPath]settings
	checkpoints      []dbus.ObjectPath
	saved            int
	failActivation   bool
	failDevice       dbus.ObjectPath
	failActiveDevice dbus.ObjectPath
	missing          bool
	nextProfile      int
	calls            [][]string
	service          *dbus.Conn
}

func newNMFixture(t *testing.T) (*adapter, *nmFixture) {
	t.Helper()
	if _, e := exec.LookPath("dbus-daemon"); e != nil {
		t.Skip("dbus-daemon unavailable")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address=1")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	address, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil {
		t.Fatal(e)
	}
	service, e := dbus.Connect(strings.TrimSpace(address))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { service.Close() })
	if _, e = service.RequestName(nm, dbus.NameFlagDoNotQueue); e != nil {
		t.Fatal(e)
	}
	client, e := dbus.Connect(strings.TrimSpace(address))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	f := &nmFixture{service: service, props: map[dbus.ObjectPath]map[string]map[string]dbus.Variant{}, profiles: map[dbus.ObjectPath]settings{}, checkpoints: []dbus.ObjectPath{}}
	f.props[nmPath] = map[string]map[string]dbus.Variant{nm: {"WirelessEnabled": dbus.MakeVariant(true), "WirelessHardwareEnabled": dbus.MakeVariant(true), "Checkpoints": dbus.MakeVariant([]dbus.ObjectPath{}), "ActiveConnections": dbus.MakeVariant([]dbus.ObjectPath{})}}
	f.props["/device/1"] = map[string]map[string]dbus.Variant{
		nm + ".Device":          {"Interface": dbus.MakeVariant("pnwifi0"), "Managed": dbus.MakeVariant(true), "DeviceType": dbus.MakeVariant(uint32(2)), "State": dbus.MakeVariant(uint32(30)), "ActiveConnection": dbus.MakeVariant(dbus.ObjectPath("/")), "AvailableConnections": dbus.MakeVariant([]dbus.ObjectPath{})},
		nm + ".Device.Wireless": {"PermHwAddress": dbus.MakeVariant("00:11:22:33:44:55"), "Mode": dbus.MakeVariant(uint32(2)), "LastScan": dbus.MakeVariant(int64(0)), "ActiveAccessPoint": dbus.MakeVariant(dbus.ObjectPath("/"))},
	}
	for _, path := range []dbus.ObjectPath{nmPath, "/device/1", "/active/1"} {
		f.exportProperties(t, path)
	}
	export := func(path dbus.ObjectPath, iface string, methods map[string]any) {
		t.Helper()
		if e := service.ExportMethodTable(methods, path, iface); e != nil {
			t.Fatal(e)
		}
	}
	export(nmPath, nm, map[string]any{
		"GetDevices": func() ([]dbus.ObjectPath, *dbus.Error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			paths := []dbus.ObjectPath{}
			for path, interfaces := range f.props {
				if _, ok := interfaces[nm+".Device"]; ok {
					paths = append(paths, path)
				}
			}
			return paths, nil
		},
		"GetDeviceByIpIface": func(name string) (dbus.ObjectPath, *dbus.Error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.missing {
				return "/", dbus.NewError(nm+".UnknownDevice", nil)
			}
			for path, interfaces := range f.props {
				if str(interfaces[nm+".Device"]["Interface"]) == name {
					return path, nil
				}
			}
			return "/", dbus.NewError(nm+".UnknownDevice", nil)
		},
		"Reload": func(flags uint32) *dbus.Error { return nil },
		"CheckpointCreate": func(paths []dbus.ObjectPath, timeout, flags uint32) (dbus.ObjectPath, *dbus.Error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.checkpoints = []dbus.ObjectPath{"/checkpoint/1"}
			f.props[nmPath][nm]["Checkpoints"] = dbus.MakeVariant(f.checkpoints)
			return "/checkpoint/1", nil
		},
		"CheckpointRollback": func(path dbus.ObjectPath) (map[string]uint32, *dbus.Error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.checkpoints = []dbus.ObjectPath{}
			f.props[nmPath][nm]["Checkpoints"] = dbus.MakeVariant(f.checkpoints)
			f.props["/device/1"][nm+".Device"]["ActiveConnection"] = dbus.MakeVariant(dbus.ObjectPath("/"))
			return map[string]uint32{"/device/1": 0}, nil
		},
		"CheckpointDestroy": func(path dbus.ObjectPath) *dbus.Error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.checkpoints = []dbus.ObjectPath{}
			f.props[nmPath][nm]["Checkpoints"] = dbus.MakeVariant(f.checkpoints)
			return nil
		},
		"ActivateConnection": func(profile, device, specific dbus.ObjectPath) (dbus.ObjectPath, *dbus.Error) {
			f.mu.Lock()
			failed := f.failDevice == device
			f.mu.Unlock()
			if failed {
				return "/", dbus.NewError(nm+".Failure", nil)
			}
			return f.activateProfile(t, profile, device)
		},
		"DeactivateConnection": func(active dbus.ObjectPath) *dbus.Error {
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, ifaces := range f.props {
				if p, ok := ifaces[nm+".Device"]; ok && obj(p["ActiveConnection"]) == active {
					p["ActiveConnection"] = dbus.MakeVariant(dbus.ObjectPath("/"))
					p["State"] = dbus.MakeVariant(uint32(30))
				}
			}
			return nil
		},
		"CheckpointAdjustRollbackTimeout": func(path dbus.ObjectPath, seconds uint32) *dbus.Error { return nil },
		"AddAndActivateConnection2": func(s settings, device, ap dbus.ObjectPath, options map[string]dbus.Variant) (dbus.ObjectPath, dbus.ObjectPath, map[string]dbus.Variant, *dbus.Error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.failActivation {
				return "/", "/", nil, dbus.NewError(nm+".Failure", []any{"secret-password-must-not-leak"})
			}
			if str(options["persist"]) != "memory" {
				return "/", "/", nil, dbus.NewError(nm+".Failure", []any{"must stage only in memory"})
			}
			f.profiles["/profile/1"] = s
			f.props["/active/1"] = map[string]map[string]dbus.Variant{nm + ".Connection.Active": {"State": dbus.MakeVariant(uint32(2)), "Connection": dbus.MakeVariant(dbus.ObjectPath("/profile/1")), "Uuid": s["connection"]["uuid"]}}
			f.props["/device/1"][nm+".Device"]["ActiveConnection"] = dbus.MakeVariant(dbus.ObjectPath("/active/1"))
			f.props["/device/1"][nm+".Device"]["State"] = dbus.MakeVariant(uint32(100))
			return "/profile/1", "/active/1", map[string]dbus.Variant{}, nil
		},
	})
	export(nmPath+"/Settings", nm+".Settings", map[string]any{"AddConnectionUnsaved": func(s settings) (dbus.ObjectPath, *dbus.Error) {
		f.mu.Lock()
		f.nextProfile++
		path := dbus.ObjectPath(fmt.Sprintf("/profile/%d", f.nextProfile))
		f.profiles[path] = s
		f.mu.Unlock()
		f.installProfile(t, path)
		return path, nil
	}, "ListConnections": func() ([]dbus.ObjectPath, *dbus.Error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		paths := []dbus.ObjectPath{}
		for path := range f.profiles {
			paths = append(paths, path)
		}
		return paths, nil
	}})
	export("/profile/1", nm+".Settings.Connection", map[string]any{
		"GetSettings": func() (settings, *dbus.Error) { f.mu.Lock(); defer f.mu.Unlock(); return f.profiles["/profile/1"], nil },
		"Save":        func() *dbus.Error { f.mu.Lock(); defer f.mu.Unlock(); f.saved++; return nil },
		"Delete":      func() *dbus.Error { f.mu.Lock(); defer f.mu.Unlock(); delete(f.profiles, "/profile/1"); return nil },
	})
	export("/device/1", nm+".Device", map[string]any{
		"GetAppliedConnection": func(flags uint32) (settings, uint64, *dbus.Error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.profiles["/profile/1"], 1, nil
		},
		"Disconnect": func() *dbus.Error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.props["/device/1"][nm+".Device"]["ActiveConnection"] = dbus.MakeVariant(dbus.ObjectPath("/"))
			return nil
		},
	})
	oldState, oldRecovery, oldSharing, oldConfig, oldNet := statePath, wifiRecoveryPath, sharingRoot, wifiConfigRoot, netClassRoot
	oldCommand, oldSystem, oldWrite, oldTools := nmCommand, nmSystemCommand, nmWrite, nmToolsReady
	nmToolsReady = func() bool { return true }
	nmWrite = func(path, text string, mode os.FileMode) error { return os.WriteFile(path, []byte(text), mode) }
	root := t.TempDir()
	statePath = filepath.Join(root, "run/change.json")
	wifiRecoveryPath = filepath.Join(root, "wifi/pending.json")
	sharingRoot = filepath.Join(root, "sharing")
	wifiConfigRoot = filepath.Join(root, "conf")
	netClassRoot = filepath.Join(root, "net")
	nmCommand = func(args ...string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, append([]string{}, args...))
		if len(args) > 1 && args[0] == "ip" && args[1] == "-j" {
			return []byte("[]"), nil
		}
		return nil, nil
	}
	nmSystemCommand = func(ctx context.Context, args []string, opts systemops.CommandOptions) ([]byte, error) {
		return nmCommand(args...)
	}
	t.Cleanup(func() {
		statePath, wifiRecoveryPath, sharingRoot, wifiConfigRoot, netClassRoot = oldState, oldRecovery, oldSharing, oldConfig, oldNet
		nmCommand, nmSystemCommand, nmWrite, nmToolsReady = oldCommand, oldSystem, oldWrite, oldTools
	})
	return &adapter{client}, f
}
func (f *nmFixture) exportProperties(t *testing.T, path dbus.ObjectPath) {
	t.Helper()
	e := f.service.ExportMethodTable(map[string]any{
		"GetAll": func(iface string) (map[string]dbus.Variant, *dbus.Error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			p := f.props[path][iface]
			out := map[string]dbus.Variant{}
			for k, v := range p {
				out[k] = v
			}
			return out, nil
		},
		"Set": func(iface, name string, value dbus.Variant) *dbus.Error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.props[path][iface][name] = value
			if iface == nm+".Device" && name == "Managed" {
				state := uint32(10)
				if boolean(value) {
					state = 30
				}
				f.props[path][iface]["State"] = dbus.MakeVariant(state)
			}
			return nil
		},
	}, path, "org.freedesktop.DBus.Properties")
	if e != nil {
		t.Fatal(e)
	}
}
func TestNMWifiRadioRealPrivateDBusRollback(t *testing.T) {
	a, f := newNMFixture(t)
	result, e := a.wifiExecute("network.wifi.radio", "admin", map[string]any{"interface": "pnwifi0", "enabled": false})
	if e != nil {
		s, _ := readNMChange(wifiRecoveryPath)
		t.Fatalf("%v; recovery=%v", e, a.rollbackWifi(s))
	}
	if result == nil {
		t.Fatal("missing result")
	}
	disabled, e := a.wifiDisabled("pnwifi0")
	if e != nil || !disabled {
		t.Fatal(disabled, e)
	}
	s, e := readNMChange(wifiRecoveryPath)
	if e != nil || s.Status != "pending" {
		t.Fatal(s, e)
	}
	if e = a.rollbackWifi(s); e != nil {
		t.Fatal(e)
	}
	disabled, e = a.wifiDisabled("pnwifi0")
	if e != nil || disabled {
		t.Fatal("radio policy not restored", e)
	}
	if e = a.rollbackWifi(s); e != nil {
		t.Fatal("rollback not idempotent", e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := false
	for _, args := range f.calls {
		if args[0] == "systemd-run" {
			seen = true
			line := strings.Join(args, " ")
			if strings.Contains(line, "python") || !strings.Contains(line, nativeNetworkHelper+" network-services rollback ") {
				t.Fatal("rollback not independent/native", line)
			}
		}
	}
	if !seen {
		t.Fatal("no rollback timer armed")
	}
}
func TestNMWifiConnectionPrivateDBusConfirmAndOldJournal(t *testing.T) {
	a, f := newNMFixture(t)
	params := map[string]any{"interface": "pnwifi0", "ssid": "Тест", "security": "wpa2", "password": "secret-password-must-not-leak"}
	if _, e := a.wifiExecute("network.wifi.connect", "admin", params); e != nil {
		t.Fatal(e)
	}
	s, e := readNMChange(wifiRecoveryPath)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(wifiRecoveryPath)
	if strings.Contains(string(raw), params["password"].(string)) {
		t.Fatal("password leaked into durable recovery")
	}
	f.mu.Lock()
	profile := f.profiles["/profile/1"]
	saved := f.saved
	f.mu.Unlock()
	if saved != 0 {
		t.Fatal("connection persisted before confirmation")
	}
	s.HashVersion = 0
	s.Previous = nil
	s.ProfileHash, e = legacyProfileSignature(profile)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.confirmWifi(s); e != nil {
		t.Fatal("legacy state could not confirm", e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saved != 1 || s.Status != "confirmed" {
		t.Fatal("confirmation not persisted")
	}
	for _, args := range f.calls {
		if strings.Contains(strings.Join(args, " "), params["password"].(string)) {
			t.Fatal("password exposed in argv")
		}
	}
}
func TestNMWifiPrivateDBusFailureRestoresAndRedacts(t *testing.T) {
	a, f := newNMFixture(t)
	f.mu.Lock()
	f.failActivation = true
	f.mu.Unlock()
	_, e := a.wifiExecute("network.wifi.connect", "admin", map[string]any{"interface": "pnwifi0", "ssid": "fixture", "security": "wpa2", "password": "secret-password-must-not-leak"})
	if e == nil || strings.Contains(e.Error(), "secret-password") {
		t.Fatal("failure leaked secret or succeeded", e)
	}
	s, e := readNMChange(wifiRecoveryPath)
	if e != nil || s.Status != "rolled-back" {
		t.Fatal("rollback missing", s, e)
	}
	if got := publicNMError(fmt.Errorf("wrapped: %w", dbus.NewError(nm+".Failure", []any{"secret"}))); strings.Contains(got, "secret") {
		t.Fatal(got)
	}
}

func TestNMMissingAndReplacedAdapterRecovery(t *testing.T) {
	a, f := newNMFixture(t)
	before := radioSnapshot{Global: true, Devices: []radioDevice{{Name: "pnwifi0", MAC: "00:11:22:33:44:55", Disabled: true, Managed: false}}}
	f.mu.Lock()
	f.missing = true
	f.mu.Unlock()
	if e := a.restoreRadios(before); e != nil {
		t.Fatal("missing adapter recovery", e)
	}
	path, _ := wifiPolicyPath(before.Devices[0].MAC)
	if _, e := os.Stat(path); e != nil {
		t.Fatal("lost absent adapter policy", e)
	}
	f.mu.Lock()
	f.missing = false
	f.props["/device/1"][nm+".Device.Wireless"]["PermHwAddress"] = dbus.MakeVariant("00:11:22:33:44:66")
	f.mu.Unlock()
	if e := a.restoreRadios(before); e == nil {
		t.Fatal("replaced adapter was modified")
	}
	other, _ := wifiPolicyPath("00:11:22:33:44:66")
	if _, e := os.Stat(other); !os.IsNotExist(e) {
		t.Fatal("replacement policy created")
	}
}
func TestNMWifiTimeoutAndRebootRecovery(t *testing.T) {
	for _, reboot := range []bool{false, true} {
		t.Run(fmt.Sprint(reboot), func(t *testing.T) {
			a, _ := newNMFixture(t)
			if _, e := a.wifiExecute("network.wifi.radio", "admin", map[string]any{"interface": "pnwifi0", "enabled": false}); e != nil {
				t.Fatal(e)
			}
			s, e := readNMChange(wifiRecoveryPath)
			if e != nil {
				t.Fatal(e)
			}
			if reboot {
				s.Boot = "previous-boot"
			} else {
				s.Deadline = 1
			}
			if e = a.currentNM(s); e != nil {
				t.Fatal(e)
			}
			if s.Status != "expired" {
				t.Fatal(s.Status)
			}
			if disabled, e := a.wifiDisabled("pnwifi0"); e != nil || disabled {
				t.Fatal("expired transaction not restored", e)
			}
			if e = a.currentNM(s); e != nil {
				t.Fatal("repeated recovery failed", e)
			}
		})
	}
}
func TestNMPackageChangeRefusesPendingAndRollbackFailure(t *testing.T) {
	_, _ = newNMFixture(t)
	for _, status := range []string{"pending", "applying", "rollback-failed"} {
		s := nmChange{state: state{ID: strings.Repeat("b", 32), Kind: "network.wifi.radio", Status: status}}
		if e := s.remember(); e != nil {
			t.Fatal(e)
		}
		if e := CheckServiceRemoval(); e == nil {
			t.Fatal("package removal accepted", status)
		}
	}
	s := nmChange{state: state{ID: strings.Repeat("b", 32), Kind: "network.wifi.radio", Status: "confirmed"}}
	if e := s.remember(); e != nil {
		t.Fatal(e)
	}
	if e := CheckServiceRemoval(); e != nil {
		t.Fatal(e)
	}
	if e := recoverNMServicesLocked(strings.Repeat("c", 32), false); e != nil {
		t.Fatal("stale timer should not connect/change state", e)
	}
}

func (f *nmFixture) installProfile(t *testing.T, path dbus.ObjectPath) {
	t.Helper()
	if e := f.service.ExportMethodTable(map[string]any{
		"GetSettings": func() (settings, *dbus.Error) { f.mu.Lock(); defer f.mu.Unlock(); return f.profiles[path], nil },
		"Save":        func() *dbus.Error { f.mu.Lock(); defer f.mu.Unlock(); f.saved++; return nil },
		"Delete":      func() *dbus.Error { f.mu.Lock(); defer f.mu.Unlock(); delete(f.profiles, path); return nil },
	}, path, nm+".Settings.Connection"); e != nil {
		t.Error(e)
	}
}
func (f *nmFixture) activateProfile(t *testing.T, profile, device dbus.ObjectPath) (dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	s, ok := f.profiles[profile]
	if !ok {
		f.mu.Unlock()
		return "/", dbus.NewError(nm+".UnknownConnection", nil)
	}
	name := str(s["connection"]["interface-name"])
	if device == "/" {
		device = dbus.ObjectPath("/device/" + strings.ReplaceAll(name, "-", "_"))
		f.props[device] = map[string]map[string]dbus.Variant{nm + ".Device": {"Interface": dbus.MakeVariant(name), "DeviceType": dbus.MakeVariant(uint32(13)), "Managed": dbus.MakeVariant(true)}}
	}
	active := dbus.ObjectPath("/active/" + filepath.Base(string(profile)))
	f.props[active] = map[string]map[string]dbus.Variant{nm + ".Connection.Active": {"State": dbus.MakeVariant(uint32(2)), "Connection": dbus.MakeVariant(profile), "Uuid": s["connection"]["uuid"]}}
	f.props[device][nm+".Device"]["ActiveConnection"] = dbus.MakeVariant(active)
	f.props[device][nm+".Device"]["State"] = dbus.MakeVariant(uint32(100))
	if f.failActiveDevice == device {
		f.props[active][nm+".Connection.Active"]["State"] = dbus.MakeVariant(uint32(4))
		f.props[device][nm+".Device"]["State"] = dbus.MakeVariant(uint32(120))
	}
	paths, _ := objectPaths(f.props[nmPath][nm]["ActiveConnections"])
	if !slices.Contains(paths, active) {
		paths = append(paths, active)
	}
	f.props[nmPath][nm]["ActiveConnections"] = dbus.MakeVariant(paths)
	f.mu.Unlock()
	f.exportProperties(t, device)
	f.exportProperties(t, active)
	return active, nil
}
func newNMSharingFixture(t *testing.T) (*adapter, *nmFixture) {
	a, f := newNMFixture(t)
	for _, name := range []string{"pneth0", "pneth1"} {
		if e := os.MkdirAll(filepath.Join(netClassRoot, name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	f.mu.Lock()
	f.nextProfile = 1
	f.props["/device/1"] = map[string]map[string]dbus.Variant{nm + ".Device": {"Interface": dbus.MakeVariant("pneth0"), "Managed": dbus.MakeVariant(true), "DeviceType": dbus.MakeVariant(uint32(1)), "State": dbus.MakeVariant(uint32(100)), "HwAddress": dbus.MakeVariant("00:11:22:33:44:55"), "ActiveConnection": dbus.MakeVariant(dbus.ObjectPath("/active/1"))}}
	f.props["/device/2"] = map[string]map[string]dbus.Variant{nm + ".Device": {"Interface": dbus.MakeVariant("pneth1"), "Managed": dbus.MakeVariant(true), "DeviceType": dbus.MakeVariant(uint32(1)), "State": dbus.MakeVariant(uint32(30)), "HwAddress": dbus.MakeVariant("00:11:22:33:44:66"), "ActiveConnection": dbus.MakeVariant(dbus.ObjectPath("/"))}}
	f.profiles["/profile/1"] = basicSettings()
	f.profiles["/profile/1"]["connection"]["uuid"] = dbus.MakeVariant("original-uplink")
	f.profiles["/profile/1"]["connection"]["interface-name"] = dbus.MakeVariant("pneth0")
	f.props["/active/1"] = map[string]map[string]dbus.Variant{nm + ".Connection.Active": {"State": dbus.MakeVariant(uint32(2)), "Connection": dbus.MakeVariant(dbus.ObjectPath("/profile/1")), "Uuid": dbus.MakeVariant("original-uplink")}}
	f.props[nmPath][nm]["ActiveConnections"] = dbus.MakeVariant([]dbus.ObjectPath{"/active/1"})
	f.mu.Unlock()
	f.exportProperties(t, "/device/2")
	if e := f.service.ExportMethodTable(map[string]any{"Disconnect": func() *dbus.Error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.props["/device/2"][nm+".Device"]["ActiveConnection"] = dbus.MakeVariant(dbus.ObjectPath("/"))
		return nil
	}}, "/device/2", nm+".Device"); e != nil {
		t.Fatal(e)
	}
	return a, f
}
func TestNMSharingPrivateDBusNATAndBridge(t *testing.T) {
	for _, mode := range []string{"nat", "bridge"} {
		t.Run(mode, func(t *testing.T) {
			a, f := newNMSharingFixture(t)
			p := map[string]any{"name": "Fixture share", "source": "pneth0", "outputs": []any{"pneth1"}, "mode": mode, "wifi": map[string]any{}, "autostart": true}
			if _, e := a.sharingExecute("network.share.save", "admin", p); e != nil {
				t.Fatal(e)
			}
			s, e := readNMChange(filepath.Join(sharingRoot, "pending.json"))
			if e != nil || s.Status != "pending" {
				t.Fatal(s, e)
			}
			f.mu.Lock()
			saved := f.saved
			f.mu.Unlock()
			if saved != 0 {
				t.Fatal("sharing persisted before consent")
			}
			if mode == "nat" {
				if e = a.rollbackNMSharing(s); e != nil {
					t.Fatal(e)
				}
				if e = a.rollbackNMSharing(s); e != nil {
					t.Fatal("rollback not idempotent", e)
				}
				groups, e := loadNMGroups()
				if e != nil || len(groups) != 0 {
					t.Fatal("groups not restored", groups, e)
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if len(f.profiles) != 1 {
					t.Fatal("temporary profiles leaked", len(f.profiles))
				}
				unreachable := false
				for _, args := range f.calls {
					if strings.Contains(strings.Join(args, " "), "unreachable default") {
						unreachable = true
					}
				}
				if !unreachable {
					t.Fatal("missing uplink fallback protection")
				}
			} else {
				if e = a.confirmNMSharing(s); e != nil {
					t.Fatal(e)
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.saved != 3 {
					t.Fatal("bridge+ports not persisted", f.saved)
				}
				bridge := f.profiles["/profile/2"]
				if fmt.Sprintf("%x", bytesValue(bridge["bridge"]["mac-address"])) != "001122334455" {
					t.Fatal("upstream MAC not preserved")
				}
			}
		})
	}
}

func TestNMDurableJournalSurvivesRuntimePublicationFailure(t *testing.T) {
	a, _ := newNMFixture(t)
	writer := nmWrite
	nmWrite = func(path, content string, mode os.FileMode) error {
		if path == statePath {
			return fmt.Errorf("injected runtime publication failure")
		}
		return writer(path, content, mode)
	}
	boot, e := bootID()
	if e != nil {
		t.Fatal(e)
	}
	s := &nmChange{state: state{ID: strings.Repeat("d", 32), Kind: "network.wifi.radio", Status: "pending", Deadline: 1e12}, Boot: boot}
	if e = s.remember(); e == nil {
		t.Fatal("injected mirror write unexpectedly succeeded")
	}
	nmWrite = writer
	got, e := currentNMChange(true)
	if e != nil || got.ID != s.ID || got.Status != "pending" {
		t.Fatalf("durable record lost: %+v %v", got, e)
	}
	if _, e = a.wifiPlan("network.wifi.radio", "admin", map[string]any{"interface": "pnwifi0", "enabled": false}); e == nil || !strings.Contains(e.Error(), "pending network change") {
		t.Fatalf("new operation could overwrite durable recovery: %v", e)
	}
	// A durable confirmation supersedes an older pending mirror too.
	s.Status = "confirmed"
	if e = writeNetworkJSON(wifiRecoveryPath, s); e != nil {
		t.Fatal(e)
	}
	got, e = currentNMChange(true)
	if e != nil || got.Status != "confirmed" {
		t.Fatalf("durable confirmation lost: %+v %v", got, e)
	}
	if e = writeNetworkJSON(statePath, map[string]any{"id": "native", "kind": "network.native", "status": "pending", "before": map[string]any{"/etc/test": "old"}}); e != nil {
		t.Fatal(e)
	}
	got, e = currentNMChange(false)
	if e != nil || got.Kind != "network.native" {
		t.Fatalf("foreign backend journal decoding changed: %+v %v", got, e)
	}
}

func TestNMFailedExpiryRemainsVisibleAndBlocksNewOperations(t *testing.T) {
	a, f := newNMFixture(t)
	if _, e := a.wifiExecute("network.wifi.radio", "admin", map[string]any{"interface": "pnwifi0", "enabled": false}); e != nil {
		t.Fatal(e)
	}
	s, e := readNMChange(wifiRecoveryPath)
	if e != nil {
		t.Fatal(e)
	}
	s.Deadline = 1
	f.mu.Lock()
	f.props["/device/1"][nm+".Device.Wireless"]["PermHwAddress"] = dbus.MakeVariant("00:11:22:33:44:66")
	f.mu.Unlock()
	if e = a.currentNM(s); e != nil {
		t.Fatal("failed rollback hid inventory", e)
	}
	visible, e := current(a)
	if e != nil || visible.Status != "rollback-failed" || visible.Error == "" {
		t.Fatalf("failed recovery unavailable: %+v %v", visible, e)
	}
	if _, e = a.wifiPlan("network.wifi.scan", "admin", map[string]any{"interface": "pnwifi0"}); e == nil {
		t.Fatal("new operation accepted during failed recovery")
	}
	f.mu.Lock()
	f.props["/device/1"][nm+".Device.Wireless"]["PermHwAddress"] = dbus.MakeVariant("00:11:22:33:44:55")
	f.mu.Unlock()
	if e = a.rollbackWifi(s); e != nil || s.Error != "" || s.Status != "rolled-back" {
		t.Fatalf("recovery could not be retried: %+v %v", s, e)
	}
}

func TestNMInventoryToleratesUnsupportedWifiPolicy(t *testing.T) {
	a, f := newNMFixture(t)
	f.mu.Lock()
	f.props["/device/1"][nm+".Device.Wireless"]["PermHwAddress"] = dbus.MakeVariant("")
	f.mu.Unlock()
	rows := []map[string]any{{"name": "pnwifi0", "kind": "wifi"}}
	if _, e := a.wifiInventory(rows); e != nil {
		t.Fatal("unsupported policy hid inventory", e)
	}
	if _, ok := rows[0]["wifi"]; ok {
		t.Fatal("unsupported radio controls exposed")
	}
	before, e := a.radioSnapshot()
	if e != nil || len(before.Devices) != 0 {
		t.Fatal("snapshot failed on unsupported adapter", before, e)
	}
	if e = a.configureRadio("pnwifi0", false); e == nil {
		t.Fatal("policy mutation accepted without stable identity")
	}
}

func TestNMDurablePendingBlocksProviderFallback(t *testing.T) {
	_, _ = newNMFixture(t)
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "absent-bus"))
	s := &nmChange{state: state{ID: strings.Repeat("e", 32), Kind: "network.wifi.radio", Status: "pending", Deadline: 1e12}}
	if e := writeNetworkJSON(wifiRecoveryPath, s); e != nil {
		t.Fatal(e)
	}
	if _, e := Operation(context.Background(), "plan", "network.wifi.scan", "admin", map[string]any{"interface": "pnwifi0"}); e == nil || !strings.Contains(e.Error(), "pending network change") {
		t.Fatalf("provider fallback bypassed the durable pending guard: %v", e)
	}
}

func TestNMImmediateConfirmationWriteFailureDoesNotClaimCommit(t *testing.T) {
	a, f := newNMSharingFixture(t)
	if e := os.MkdirAll(filepath.Join(netClassRoot, "pneth2"), 0700); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.props["/device/3"] = map[string]map[string]dbus.Variant{nm + ".Device": {"Interface": dbus.MakeVariant("pneth2"), "Managed": dbus.MakeVariant(true), "DeviceType": dbus.MakeVariant(uint32(1)), "State": dbus.MakeVariant(uint32(30)), "HwAddress": dbus.MakeVariant("00:11:22:33:44:77"), "ActiveConnection": dbus.MakeVariant(dbus.ObjectPath("/"))}}
	f.mu.Unlock()
	f.exportProperties(t, "/device/3")
	p := map[string]any{"name": "Fixture share", "source": "pneth0", "outputs": []any{"pneth1", "pneth2"}, "mode": "bridge", "wifi": map[string]any{}, "autostart": true}
	if _, e := a.sharingExecute("network.share.save", "admin", p); e != nil {
		t.Fatal(e)
	}
	s, e := readNMChange(filepath.Join(sharingRoot, "pending.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = a.confirmNMSharing(s); e != nil {
		t.Fatal(e)
	}
	groups, e := loadNMGroups()
	if e != nil {
		t.Fatal(e)
	}
	writer := nmWrite
	injected := false
	nmWrite = func(path, content string, mode os.FileMode) error {
		if !injected && path == filepath.Join(sharingRoot, "pending.json") && strings.Contains(content, `"status":"confirmed"`) {
			injected = true
			return fmt.Errorf("injected durable commit failure")
		}
		return writer(path, content, mode)
	}
	_, e = a.sharingExecute("network.share.remove-port", "admin", map[string]any{"id": groups[0].ID, "interface": "pneth1"})
	if !injected || e == nil || strings.Contains(e.Error(), "confirmed") {
		t.Fatalf("false confirmation after failed commit: %v", e)
	}
	restored, e := loadNMGroups()
	if e != nil || len(restored) != 1 || !slices.Contains(restored[0].Outputs, "pneth1") {
		t.Fatalf("uncommitted removal not restored: %+v %v", restored, e)
	}
}

func TestNMInventoryToleratesAnAdapterRemovedAfterLinkRead(t *testing.T) {
	a, f := newNMFixture(t)
	f.mu.Lock()
	f.missing = true
	f.mu.Unlock()
	rows := []map[string]any{{"name": "pnwifi0", "kind": "wifi"}}
	if _, e := a.wifiInventory(rows); e != nil {
		t.Fatal("stale interface hid the complete network inventory", e)
	}
	if _, ok := rows[0]["wifi"]; ok {
		t.Fatal("controls exposed for removed adapter")
	}
}

func TestNMWifiConfirmationFailureRestoresPreviousConnection(t *testing.T) {
	for _, stage := range []string{"before-destroy", "after-destroy", "legacy-after-destroy"} {
		t.Run(stage, func(t *testing.T) {
			a, f := newNMFixture(t)
			const original = "previous-wifi-uuid"
			f.mu.Lock()
			f.profiles["/profile/original"] = wifiConnection(wifiChoice{SSID: []byte("original"), Security: "open"}, "pnwifi0", original)
			f.mu.Unlock()
			f.installProfile(t, "/profile/original")
			if _, e := f.activateProfile(t, "/profile/original", "/device/1"); e != nil {
				t.Fatal(e)
			}
			if _, e := a.wifiExecute("network.wifi.connect", "admin", map[string]any{"interface": "pnwifi0", "ssid": "fixture", "security": "wpa2", "password": "fixture-password"}); e != nil {
				t.Fatal(e)
			}
			s, e := readNMChange(wifiRecoveryPath)
			if e != nil || s.Previous["pnwifi0"] == nil || *s.Previous["pnwifi0"] != original {
				t.Fatalf("previous connection missing: %+v %v", s, e)
			}
			if stage == "legacy-after-destroy" {
				s.Previous = nil
				if e = s.remember(); e != nil {
					t.Fatal(e)
				}
			}
			writer := nmWrite
			injected := false
			nmWrite = func(path, content string, mode os.FileMode) error {
				match := strings.Contains(content, `"status":"confirmed"`)
				if stage == "before-destroy" {
					match = strings.Contains(content, `"confirming":true`)
				}
				if !injected && path == wifiRecoveryPath && match {
					injected = true
					return fmt.Errorf("injected confirmation write failure")
				}
				return writer(path, content, mode)
			}
			if e = a.confirmWifi(s); e == nil || !injected {
				t.Fatal("confirmation should fail", e)
			}
			nmWrite = writer
			durable, e := readNMChange(wifiRecoveryPath)
			if e != nil || durable.Status != "pending" {
				t.Fatalf("false durable confirmation: %+v %v", durable, e)
			}
			checkpoints, e := a.checkpoints()
			if e != nil || (len(checkpoints) > 0) != (stage == "before-destroy") {
				t.Fatal("unexpected checkpoint boundary", checkpoints, e)
			}
			e = a.rollbackWifi(durable)
			if stage == "legacy-after-destroy" {
				if e == nil {
					t.Fatal("legacy ambiguity must require recovery")
				}
				profiles, pe := a.profiles()
				if pe != nil || profiles[durable.NewUUID].Path == "" {
					t.Fatal("legacy ambiguous recovery deleted active profile", pe)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = a.rollbackWifi(durable); e != nil {
				t.Fatal("repeated rollback", e)
			}
			_, props, e := a.device("pnwifi0")
			if e != nil {
				t.Fatal(e)
			}
			active, e := a.props(obj(props["ActiveConnection"]), nm+".Connection.Active")
			if e != nil || str(active["Uuid"]) != original {
				t.Fatal("previous connection not restored", active, e)
			}
			profiles, e := a.profiles()
			if e != nil || profiles[durable.NewUUID].Path != "" {
				t.Fatal("staged profile not removed", e)
			}
		})
	}
}

func TestNMSharingAPChannelUsesHelperJSONDecoder(t *testing.T) {
	a, f := newNMSharingFixture(t)
	bin := t.TempDir()
	if e := os.WriteFile(filepath.Join(bin, "iw"), []byte("#!/bin/sh\nexit 1\n"), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	if e := os.MkdirAll(filepath.Join(netClassRoot, "pneth1", "phy80211"), 0700); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.props["/device/2"][nm+".Device"]["DeviceType"] = dbus.MakeVariant(uint32(2))
	f.props["/device/2"][nm+".Device.Wireless"] = map[string]dbus.Variant{"PermHwAddress": dbus.MakeVariant("00:11:22:33:44:66"), "WirelessCapabilities": dbus.MakeVariant(uint32(0x40))}
	f.mu.Unlock()
	command := nmCommand
	nmCommand = func(args ...string) ([]byte, error) {
		if len(args) > 1 && args[0] == "iw" && args[1] == "phy" {
			return []byte("* 2412 MHz [1] (20.0 dBm)\n* 2437 MHz [6] (20.0 dBm)"), nil
		}
		return command(args...)
	}
	for _, value := range []string{"0", "6", "1.5", `"6"`, "9999999999999999999999999"} {
		var p map[string]any
		raw := `{"name":"AP fixture","source":"pneth0","outputs":["pneth1"],"mode":"nat","wifi":{"pneth1":{"ssid":"fixture","password":"fixture-password","band":"bg","channel":` + value + `}},"autostart":false}`
		if e := systemops.Decode([]byte(raw), &p); e != nil {
			t.Fatal(e)
		}
		g, _, e := a.reviewNMSharing(p, nil)
		if value == "0" || value == "6" {
			want := 1
			if value == "6" {
				want = 6
			}
			if e != nil || g.Wifi["pneth1"].Channel != want {
				t.Fatalf("channel %s rejected: %+v %v", value, g, e)
			}
		} else if e == nil {
			t.Fatal("invalid channel accepted", value)
		}
	}
}

func TestNMSharingRefreshContinuesAfterPortFailure(t *testing.T) {
	a, f := newNMSharingFixture(t)
	p := map[string]any{"name": "Fixture", "source": "pneth0", "outputs": []any{"pneth1"}, "mode": "bridge", "wifi": map[string]any{}, "autostart": true}
	if _, e := a.sharingExecute("network.share.save", "admin", p); e != nil {
		t.Fatal(e)
	}
	groups, e := loadNMGroups()
	if e != nil {
		t.Fatal(e)
	}
	g := groups[0]
	f.mu.Lock()
	f.props[nmPath][nm]["ActiveConnections"] = dbus.MakeVariant([]dbus.ObjectPath{})
	f.props["/device/2"][nm+".Device"]["ActiveConnection"] = dbus.MakeVariant(dbus.ObjectPath("/"))
	f.mu.Unlock()
	f.mu.Lock()
	f.failDevice = "/device/1"
	f.mu.Unlock()
	if e = a.activateNMGroup(g, false); e == nil {
		t.Fatal("strict activation ignored failed port")
	}
	if e = a.activateNMGroup(g, true); e != nil {
		t.Fatal("recovery did not tolerate failed port", e)
	}
	_, props, e := a.device("pneth1")
	if e != nil || obj(props["ActiveConnection"]) == "/" {
		t.Fatal("remaining port was skipped", e)
	}
}

func TestNMSharingFailedRestoreRetainsStagedProfiles(t *testing.T) {
	a, f := newNMSharingFixture(t)
	p := map[string]any{"name": "Fixture", "source": "pneth0", "outputs": []any{"pneth1"}, "mode": "bridge", "wifi": map[string]any{}, "autostart": true}
	if _, e := a.sharingExecute("network.share.save", "admin", p); e != nil {
		t.Fatal(e)
	}
	s, e := readNMChange(filepath.Join(sharingRoot, "pending.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = a.call(nmPath, nm+".CheckpointDestroy", s.Checkpoint).Err; e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.failDevice = "/device/1"
	f.mu.Unlock()
	if e = a.rollbackNMSharing(s); e == nil {
		t.Fatal("failed original connection activation not reported")
	}
	profiles, e := a.profiles()
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range s.NewUUIDs {
		if profiles[id].Path == "" {
			t.Fatal("staged profile deleted before restore", id)
		}
	}
	f.mu.Lock()
	f.failDevice = ""
	f.failActiveDevice = "/device/1"
	f.mu.Unlock()
	if e = a.rollbackNMSharing(s); e == nil {
		t.Fatal("asynchronous activation failure treated as restored")
	}
	profiles, e = a.profiles()
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range s.NewUUIDs {
		if profiles[id].Path == "" {
			t.Fatal("staged profile deleted after asynchronous restore failure", id)
		}
	}
	f.mu.Lock()
	f.failActiveDevice = ""
	f.mu.Unlock()
	if e = a.rollbackNMSharing(s); e != nil {
		t.Fatal("retry failed", e)
	}
	profiles, e = a.profiles()
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range s.NewUUIDs {
		if profiles[id].Path != "" {
			t.Fatal("staged profile retained after successful restore", id)
		}
	}
}

func TestNMIPv6ProfileCloneRestoresDBusStructSignatures(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(fmt.Sprint(populated), func(t *testing.T) {
			a, f := newNMSharingFixture(t)
			addresses := []nmIPv6Address{}
			routes := []nmIPv6Route{}
			if populated {
				addresses = append(addresses, nmIPv6Address{make([]byte, 16), 64, make([]byte, 16)})
				routes = append(routes, nmIPv6Route{make([]byte, 16), 64, make([]byte, 16), 10})
			}
			f.mu.Lock()
			f.profiles["/profile/1"]["ipv6"] = map[string]dbus.Variant{"method": dbus.MakeVariant("disabled"), "addresses": dbus.MakeVariant(addresses), "routes": dbus.MakeVariant(routes)}
			f.mu.Unlock()
			settings, e := a.getSettings("/profile/1")
			if e != nil {
				t.Fatal(e)
			}
			copied, e := cloneNMFields("ipv6", settings["ipv6"])
			if e != nil {
				t.Fatal(e)
			}
			if copied["addresses"].Signature().String() != "a(ayuay)" || copied["routes"].Signature().String() != "a(ayuayu)" {
				t.Fatal("legacy IPv6 signatures lost", copied)
			}
			if len(copied["addresses"].Value().([]nmIPv6Address)) != len(addresses) || len(copied["routes"].Value().([]nmIPv6Route)) != len(routes) {
				t.Fatal("legacy IPv6 contents lost")
			}
		})
	}
}

func TestNMSharingPortsBindPermanentMAC(t *testing.T) {
	for _, wireless := range []bool{false, true} {
		for _, permanent := range []string{"00:11:22:33:44:66", "", "invalid"} {
			t.Run(fmt.Sprintf("wifi=%v/perm=%s", wireless, permanent), func(t *testing.T) {
				a, f := newNMSharingFixture(t)
				p := map[string]any{"name": "Fixture", "source": "pneth0", "outputs": []any{"pneth1"}, "mode": "nat", "wifi": map[string]any{}, "autostart": false}
				g, _, e := a.reviewNMSharing(p, nil)
				if e != nil {
					t.Fatal(e)
				}
				iface, kind := nm+".Device.Wired", "802-3-ethernet"
				if wireless {
					iface, kind = nm+".Device.Wireless", "802-11-wireless"
					g.Wifi = map[string]nmAP{"pneth1": {SSID: "fixture", Band: "bg", Channel: 6}}
					p["wifi"] = map[string]any{"pneth1": map[string]any{"password": "fixture-password"}}
				}
				f.mu.Lock()
				f.props["/device/2"][nm+".Device"]["HwAddress"] = dbus.MakeVariant("02:aa:bb:cc:dd:ee")
				if wireless {
					f.props["/device/2"][nm+".Device"]["DeviceType"] = dbus.MakeVariant(uint32(2))
				}
				f.props["/device/2"][iface] = map[string]dbus.Variant{"PermHwAddress": dbus.MakeVariant(permanent)}
				f.mu.Unlock()
				change := &nmChange{state: state{Kind: "network.share.save"}, NewProfiles: map[string]string{}}
				g, e = a.buildNMGroup(g, p, nil, change)
				if e != nil {
					t.Fatal(e)
				}
				profiles, e := a.profiles()
				if e != nil {
					t.Fatal(e)
				}
				bound := bytesValue(profiles[g.Profiles["pneth1"]].Settings[kind]["mac-address"])
				if permanent != "00:11:22:33:44:66" {
					if len(bound) != 0 {
						t.Fatalf("unavailable permanent MAC bound to current address: %x", bound)
					}
					return
				}
				if fmt.Sprintf("%x", bound) != "001122334466" {
					t.Fatalf("randomized current MAC used: %x", bound)
				}
				if match, e := a.matchesNMAdapter(g, "pneth1", profiles); e != nil || !match {
					t.Fatal("permanent adapter rejected", match, e)
				}
				f.mu.Lock()
				f.props["/device/2"][iface]["PermHwAddress"] = dbus.MakeVariant("00:11:22:33:44:77")
				f.mu.Unlock()
				if match, e := a.matchesNMAdapter(g, "pneth1", profiles); e != nil || match {
					t.Fatal("replacement adapter accepted", match, e)
				}
			})
		}
	}
}

func TestNMSharingLegacyWiredBindingWithoutPermanentMAC(t *testing.T) {
	for _, test := range []struct {
		name, permanent, current, identity string
		want                               bool
	}{
		{"legacy unchanged", "", "00:11:22:33:44:66", "pneth1", true},
		{"different physical device", "", "00:11:22:33:44:66", "other-device", false},
		{"different current address", "", "00:11:22:33:44:77", "pneth1", false},
		{"missing saved identity", "", "00:11:22:33:44:66", "", false},
		{"permanent mismatch wins", "00:11:22:33:44:77", "00:11:22:33:44:66", "pneth1", false},
		{"permanent match wins", "00:11:22:33:44:66", "02:aa:bb:cc:dd:ee", "pneth1", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, f := newNMSharingFixture(t)
			f.mu.Lock()
			f.props["/device/2"][nm+".Device"]["HwAddress"] = dbus.MakeVariant(test.current)
			f.props["/device/2"][nm+".Device.Wired"] = map[string]dbus.Variant{"PermHwAddress": dbus.MakeVariant(test.permanent)}
			f.mu.Unlock()
			g := nmGroup{Profiles: map[string]string{"pneth1": "legacy"}, Identities: map[string]string{"pneth1": test.identity}}
			profiles := map[string]nmProfile{"legacy": {Settings: settings{"connection": {"type": dbus.MakeVariant("802-3-ethernet")}, "802-3-ethernet": {"mac-address": dbus.MakeVariant([]byte{0, 17, 34, 51, 68, 102})}}}}
			match, e := a.matchesNMAdapter(g, "pneth1", profiles)
			if e != nil || match != test.want {
				t.Fatal("legacy identity match", match, e)
			}
		})
	}
}
