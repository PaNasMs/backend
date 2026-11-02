package network

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/godbus/dbus/v5"
	"panasms.local/backend/internal/systemops"
)

var nmWrite = systemops.AtomicWrite
var nmCommand = command
var nmSystemCommand = systemops.Command

var wifiRecoveryPath = "/var/lib/panasms-agent/network-wifi/pending.json"
var sharingRoot = "/var/lib/panasms-agent/network-sharing"

const nativeNetworkHelper = "/usr/lib/panasms/panasms-system-helper"

type nmGroup struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Source     string             `json:"source"`
	Outputs    []string           `json:"outputs"`
	Mode       string             `json:"mode"`
	Wifi       map[string]nmAP    `json:"wifi"`
	Enabled    bool               `json:"enabled"`
	Autostart  bool               `json:"autostart"`
	Bridge     string             `json:"bridge"`
	Subnet     string             `json:"subnet,omitempty"`
	Slot       int                `json:"slot"`
	Identities map[string]string  `json:"identities"`
	Previous   map[string]*string `json:"previous"`
	Profiles   map[string]string  `json:"profiles"`
	Provider   string             `json:"provider,omitempty"`
}
type nmAP struct {
	SSID    string `json:"ssid"`
	Band    string `json:"band"`
	Channel int    `json:"channel"`
}
type nmChange struct {
	state
	HashVersion    int                `json:"hashVersion,omitempty"`
	Boot           string             `json:"boot"`
	RadioBefore    bool               `json:"radioBefore"`
	RadioAfter     bool               `json:"radioAfter"`
	AdaptersBefore *radioSnapshot     `json:"adaptersBefore,omitempty"`
	NewUUID        string             `json:"newUUID,omitempty"`
	Before         []nmGroup          `json:"before,omitempty"`
	After          []nmGroup          `json:"after,omitempty"`
	Previous       map[string]*string `json:"previous,omitempty"`
	NewUUIDs       []string           `json:"newUUIDs,omitempty"`
	NewProfiles    map[string]string  `json:"newProfiles,omitempty"`
	ProfileHashes  map[string]string  `json:"profileHashes,omitempty"`
	Working        *nmGroup           `json:"working,omitempty"`
}

func readNMChange(path string) (*nmChange, error) {
	raw, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var base state
	if e = json.Unmarshal(raw, &base); e != nil {
		return nil, e
	}
	if !supplementalKind(base.Kind) {
		return &nmChange{state: base}, nil
	}
	var s nmChange
	if e = json.Unmarshal(raw, &s); e != nil {
		return nil, e
	}
	return &s, nil
}
func writeNetworkJSON(path string, value any) error {
	raw, e := json.Marshal(value)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	return nmWrite(path, string(raw), 0600)
}
func (s *nmChange) remember() error {
	path := wifiRecoveryPath
	if strings.HasPrefix(s.Kind, "network.share.") {
		path = filepath.Join(sharingRoot, "pending.json")
	}
	// The durable rollback record must survive a crash before the /run state is published.
	if e := writeNetworkJSON(path, s); e != nil {
		return e
	}
	return writeNetworkJSON(statePath, s)
}
func bootID() (string, error) {
	raw, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(raw)), e
}
func randomID() (string, error) {
	raw := make([]byte, 16)
	_, e := rand.Read(raw)
	return hex.EncodeToString(raw), e
}
func randomUUID() (string, error) {
	raw := make([]byte, 16)
	if _, e := rand.Read(raw); e != nil {
		return "", e
	}
	raw[6] = (raw[6] & 15) | 64
	raw[8] = (raw[8] & 63) | 128
	x := hex.EncodeToString(raw)
	return x[:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:], nil
}
func (s *nmChange) timerUnit() string {
	prefix := "panasms-wifi-rollback-"
	if strings.HasPrefix(s.Kind, "network.share.") {
		prefix = "panasms-share-rollback-"
	}
	return prefix + s.ID
}
func (s *nmChange) arm(seconds int) error {
	_, e := nmCommand("systemd-run", "--quiet", "--collect", "--unit="+s.timerUnit(), fmt.Sprintf("--on-active=%ds", seconds), "--timer-property=AccuracySec=1s", "--property=Restart=on-failure", "--property=RestartSec=3s", nativeNetworkHelper, "network-services", "rollback", s.ID)
	return e
}
func (s *nmChange) disarm() error {
	_, e := nmSystemCommand(context.Background(), []string{"systemctl", "stop", s.timerUnit() + ".timer"}, systemops.CommandOptions{Accepted: []int{0, 5}})
	return e
}
func legacyProfileSignature(s settings) (string, error) {
	clean := map[string]map[string]any{}
	for section, fields := range s {
		clean[section] = map[string]any{}
		for key, value := range fields {
			if section != "connection" || key != "timestamp" {
				clean[section][key] = plain(value.Value())
			}
		}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if e := enc.Encode([]any{"network-state", map[string]any{}, clean}); e != nil {
		return "", e
	}
	var ascii strings.Builder
	for _, r := range strings.TrimSuffix(b.String(), "\n") {
		if r < 128 {
			ascii.WriteRune(r)
		} else if r <= 0xffff {
			fmt.Fprintf(&ascii, `\u%04x`, r)
		} else {
			a, b := utf16.EncodeRune(r)
			fmt.Fprintf(&ascii, `\u%04x\u%04x`, a, b)
		}
	}
	sum := sha256.Sum256([]byte(ascii.String()))
	return hex.EncodeToString(sum[:]), nil
}
func (s *nmChange) matchesProfile(actual settings, expected string) bool {
	if s.HashVersion == 1 {
		return signature(actual) == expected
	}
	got, e := legacyProfileSignature(actual)
	return e == nil && got == expected
}

type nmProfile struct {
	Path     dbus.ObjectPath
	Settings settings
}

func (a *adapter) profiles() (map[string]nmProfile, error) {
	var paths []dbus.ObjectPath
	if e := a.call(nmPath+"/Settings", nm+".Settings.ListConnections").Store(&paths); e != nil {
		return nil, e
	}
	result := map[string]nmProfile{}
	for _, path := range paths {
		s, e := a.getSettings(path)
		if e != nil {
			return nil, e
		}
		result[str(s["connection"]["uuid"])] = nmProfile{path, s}
	}
	return result, nil
}
func (a *adapter) deleteProfiles(ids []string) error {
	profiles, e := a.profiles()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if p, ok := profiles[id]; ok {
			if e = a.call(p.Path, nm+".Settings.Connection.Delete").Err; e != nil {
				return e
			}
		}
	}
	return nil
}

func currentNMChange(publish bool) (*nmChange, error) {
	runtime, e := readNMChange(statePath)
	if e != nil {
		return nil, e
	}
	current := runtime
	records := []*nmChange{}
	for _, path := range []string{wifiRecoveryPath, filepath.Join(sharingRoot, "pending.json")} {
		saved, e := readNMChange(path)
		if e != nil {
			return nil, e
		}
		if saved == nil {
			continue
		}
		if !supplementalKind(saved.Kind) {
			return nil, fmt.Errorf("Invalid network recovery state")
		}
		records = append(records, saved)
		if runtime != nil && runtime.ID == saved.ID {
			current = saved
		}
	}
	for _, saved := range records {
		if !active(&saved.state) {
			continue
		}
		if current != nil && active(&current.state) && current.ID != saved.ID {
			return nil, fmt.Errorf("Confirm or roll back the pending network change first")
		}
		current = saved
	}
	if publish && current != nil && digest(current) != digest(runtime) {
		if e = writeNetworkJSON(statePath, current); e != nil {
			return nil, e
		}
	}
	return current, nil
}
