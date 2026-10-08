package networknative

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/networkd"
)

type transaction struct {
	Sharing      bool               `json:"sharing"`
	GroupsBefore []Group            `json:"groupsBefore,omitempty"`
	GroupsAfter  []Group            `json:"groupsAfter,omitempty"`
	ID           string             `json:"id"`
	Kind         string             `json:"kind"`
	Interface    string             `json:"interface"`
	User         string             `json:"user"`
	Status       string             `json:"status"`
	Deadline     int64              `json:"deadline"`
	Boot         string             `json:"boot"`
	Addresses    []string           `json:"addresses"`
	Error        string             `json:"error,omitempty"`
	Before       map[string]*string `json:"before"`
	Applied      map[string]*string `json:"applied"`
	WifiBefore   *wifiConfig        `json:"wifiBefore,omitempty"`
	WifiAfter    *wifiConfig        `json:"wifiAfter,omitempty"`
}

var pending = "/run/panasms-network/change.json"

func boot() string { b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id"); return string(b) }
func save(t *transaction) error {
	if e := write(root+"/pending.json", t); e != nil {
		return e
	}
	return write(pending, t)
}
func loadTransaction() (*transaction, error) {
	var t transaction
	e := read(root+"/pending.json", &t)
	if os.IsNotExist(e) {
		return nil, nil
	}
	return &t, e
}
func activeTransaction(t *transaction) bool {
	return t != nil && (t.Status == "pending" || t.Status == "applying" || t.Status == "rollback-failed")
}
func publicTransaction(t *transaction) map[string]any {
	return map[string]any{"id": t.ID, "kind": t.Kind, "interface": t.Interface, "user": t.User, "status": t.Status, "deadline": t.Deadline, "addresses": t.Addresses, "error": t.Error}
}
func rollback(t *transaction) error {
	t.Status = "rollback-failed"
	if t.Sharing {
		for _, g := range changedGroups(t.GroupsAfter, t.GroupsBefore) {
			if g.Enabled {
				if e := DeactivateGroup(g); e != nil {
					t.Error = e.Error()
					_ = save(t)
					return e
				}
			}
		}
		if e := write(groupsPath, t.GroupsBefore); e != nil {
			return e
		}

	}
	for p, v := range t.Before {
		if e := setFile(p, v); e != nil {
			t.Error = e.Error()
			_ = save(t)
			return e
		}
	}
	if t.Sharing {
		for _, g := range changedGroups(t.GroupsBefore, t.GroupsAfter) {
			if g.Enabled {
				if e := ActivateGroup(g); e != nil {
					t.Error = e.Error()
					_ = save(t)
					return e
				}
			}
		}
	}
	if t.WifiBefore != nil {
		if e := applyRadioOrWifi(*t.WifiBefore); e != nil {
			t.Error = e.Error()
			_ = save(t)
			return e
		}
	}
	t.Status = "rolled-back"
	t.Error = ""
	return save(t)
}
func Recover(force bool) error {
	unlock, e := networkd.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	t, e := loadTransaction()
	if e != nil {
		return e
	}
	if activeTransaction(t) && (force || t.Boot != boot() || time.Now().Unix() >= t.Deadline) {
		return rollback(t)
	}
	return nil
}
func Operation(mode, action, user string, p map[string]any) (json.RawMessage, error) {
	unlock, e := networkd.Lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	t, e := loadTransaction()
	if e != nil {
		return nil, e
	}
	if activeTransaction(t) && (t.Boot != boot() || time.Now().Unix() >= t.Deadline) {
		if e = rollback(t); e != nil {
			return nil, e
		}
	}
	if action == "network.confirm" || action == "network.rollback" {
		if t == nil || t.Status != "pending" || t.User != user || p["id"] != t.ID {
			return nil, fmt.Errorf("This network change has expired or is owned by another user")
		}
		if mode == "plan" {
			return json.Marshal(map[string]any{"target": t.Interface, "confirmation": t.ID, "fingerprint": hash([]any{action, p, t.ID, t.Applied}), "details": []string{t.Interface}})
		}
		if action == "network.rollback" {
			e = rollback(t)
		} else {
			for path, v := range t.Applied {
				current, err := fileState(path)
				if err != nil {
					return nil, err
				}
				if hash(current) != hash(v) {
					return nil, fmt.Errorf("Network configuration changed externally; roll back and review it again")
				}
			}
			t.Status = "confirmed"
			e = save(t)
		}
		if e != nil {
			return nil, e
		}
		return json.Marshal(map[string]any{"message": "Network settings " + t.Status})
	}
	var current struct {
		Status string `json:"status"`
	}
	if e = read(pending, &current); e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if current.Status == "pending" || current.Status == "applying" || current.Status == "rollback-failed" {
		return nil, fmt.Errorf("Confirm or roll back the pending network change first")
	}
	if strings.HasPrefix(action, "network.share.") {
		return sharingOperation(mode, action, user, p)
	}
	c, e := wifiOperation(action, p)
	if e != nil {
		return nil, e
	}
	before, e := wifiSettings(c.Name)
	if e != nil {
		return nil, e
	}
	if mode == "plan" {
		return json.Marshal(map[string]any{"target": c.Name, "confirmation": c.Name, "details": []string{c.Name}, "fingerprint": hash([]any{action, p, before, Identity(c.Name)})})
	}
	if action == "network.wifi.scan" {
		if e = Scan(c.Name); e != nil {
			return nil, e
		}
		return json.Marshal(map[string]any{"message": "Wi-Fi scan requested"})
	}
	files, e := wifiFiles(c)
	if e != nil {
		return nil, e
	}
	if e = validateFiles(files); e != nil {
		return nil, e
	}
	raw, _ := json.Marshal(c)
	files[wifiPath(c.Name)] = text(string(raw))
	t = &transaction{ID: ident(), Kind: "network.native", Interface: c.Name, User: user, Status: "applying", Deadline: time.Now().Unix() + 150, Boot: boot(), Before: map[string]*string{}, Applied: files, WifiBefore: &before, WifiAfter: &c, Addresses: []string{}}
	for path := range files {
		v, err := fileState(path)
		if err != nil {
			return nil, err
		}
		t.Before[path] = v
	}
	if e = save(t); e != nil {
		return nil, e
	}
	// Arm recovery before any network changes; boot recovery uses the durable record.
	if e = arm(t); e != nil {
		t.Status = "rolled-back"
		_ = save(t)
		return nil, e
	}
	e = write(wifiPath(c.Name), c)
	if e == nil {
		e = applyRadioOrWifi(c)
	}
	if e == nil && action == "network.wifi.connect" {
		deadline := time.Now().Add(50 * time.Second)
		connected := false
		for time.Now().Before(deadline) {
			raw, err := wpa(c.Name, "STATUS")
			if err == nil && fields(raw)["wpa_state"] == "COMPLETED" && hasGlobalAddress(Addresses(c.Name)) {
				connected = true
				break
			}
			time.Sleep(time.Second)
		}
		if !connected {
			e = &systemops.Rejected{Message: "Wi-Fi connection timed out; check password, signal and router settings"}
		}
	}
	if e != nil {
		original := e
		if recovery := rollback(t); recovery != nil {
			return nil, fmt.Errorf("Wi-Fi operation failed and rollback needs attention: %v", recovery)
		}
		if systemops.IsRejected(original) {
			return nil, original
		}
		return nil, fmt.Errorf("%v; previous settings restored", original)
	}
	for path := range t.Before {
		value, err := fileState(path)
		if err != nil {
			if recovery := rollback(t); recovery != nil {
				return nil, fmt.Errorf("Network verification failed and rollback needs attention: %w", recovery)
			}
			return nil, err
		}
		t.Applied[path] = value
	}
	t.Status = "pending"
	t.Addresses = Addresses(c.Name)
	if e = save(t); e != nil {
		return nil, e
	}
	return json.Marshal(map[string]any{"message": "Network changes await confirmation", "change": publicTransaction(t)})
}
func initializeWifi(groups []Group, first bool) error {
	paths, e := filepath.Glob(root + "/wifi/*.json")
	if e != nil {
		return e
	}
	for _, p := range paths {
		var c wifiConfig
		if e = read(p, &c); e != nil {
			return e
		}
		reserved := false
		for _, g := range groups {
			if g.Enabled {
				for _, output := range g.Outputs {
					reserved = reserved || output == c.Name
				}
			}
		}
		if reserved || APActive(c.Name) {
			continue
		}
		if !first && (!c.Enabled || !c.Connected || len(c.Profiles) == 0 || run("systemctl", "is-active", "--quiet", wifiUnit(c.Name)) == nil) {
			continue
		}
		if Wireless(c.Name) && Identity(c.Name) == c.Identity {
			if e = ApplyWifi(c); e != nil {
				return e
			}
		}
	}
	return nil
}
