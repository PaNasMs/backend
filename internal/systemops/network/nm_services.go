package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/godbus/dbus/v5"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/networkd"
)

func supplementalKind(kind string) bool {
	return strings.HasPrefix(kind, "network.wifi.") || strings.HasPrefix(kind, "network.share.")
}
func (a *adapter) currentNM(s *nmChange) error {
	if s == nil || !active(&s.state) || s.Status == "rollback-failed" {
		return nil
	}
	boot, e := bootID()
	if e != nil {
		return e
	}
	expired := float64(time.Now().UnixNano())/1e9 >= s.Deadline || s.Boot != boot
	if strings.HasPrefix(s.Kind, "network.share.") && s.Checkpoint != "" {
		checkpoints, e := a.checkpoints()
		if e != nil {
			return e
		}
		expired = expired || !slices.Contains(checkpoints, s.Checkpoint)
	}
	if !expired {
		return nil
	}
	if strings.HasPrefix(s.Kind, "network.share.") {
		e = a.rollbackNMSharing(s)
	} else {
		e = a.rollbackWifi(s)
	}
	if e != nil {
		s.Status = "rollback-failed"
		s.Error = publicNMError(e)
		return s.remember()
	}
	s.Status = "expired"
	s.Error = ""
	return s.remember()
}
func supplementalOperation(mode, action, user string, p map[string]any) (json.RawMessage, error) {
	unlock, e := networkd.Lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	a, e := connect()
	if e != nil {
		return nil, e
	}
	defer a.bus.Close()
	if _, e = current(a); e != nil {
		return nil, e
	}
	s, e := currentNMChange(true)
	if e != nil {
		return nil, e
	}
	if s != nil && supplementalKind(s.Kind) {
		if e = a.currentNM(s); e != nil {
			return nil, e
		}
	}
	var result any
	switch {
	case strings.HasPrefix(action, "network.wifi."):
		if mode == "plan" {
			result, e = a.wifiPlan(action, user, p)
		} else {
			result, e = a.wifiExecute(action, user, p)
		}
	case strings.HasPrefix(action, "network.share."):
		if mode == "plan" {
			result, e = a.sharingPlan(action, user, p)
		} else {
			result, e = a.sharingExecute(action, user, p)
		}
	case action == "network.confirm" || action == "network.rollback":
		if s == nil || !supplementalKind(s.Kind) || (s.Status != "pending" && !(action == "network.rollback" && s.Status == "rollback-failed")) || p["id"] != s.ID || s.User != user {
			return nil, fmt.Errorf("This network change has expired or is no longer pending")
		}
		if mode == "plan" {
			result = map[string]any{"target": s.Interface, "confirmation": s.ID, "details": []string{s.Interface}, "fingerprint": digest([]any{action, p, s.ID, s.Checkpoint})}
			break
		}
		if strings.HasPrefix(s.Kind, "network.share.") {
			if action == "network.confirm" {
				e = a.confirmNMSharing(s)
			} else {
				e = a.rollbackNMSharing(s)
			}
		} else {
			if action == "network.confirm" {
				e = a.confirmWifi(s)
			} else {
				e = a.rollbackWifi(s)
				if e == nil {
					e = s.disarm()
				}
			}
		}
		message := "Previous network settings restored"
		if s.Status == "confirmed" {
			message = "Network settings confirmed"
		}
		result = map[string]any{"message": message}
	default:
		return nil, fmt.Errorf("Unknown network operation")
	}
	if e != nil {
		return nil, &systemops.Rejected{Message: publicNMError(e)}
	}
	return json.Marshal(result)
}
func publicNMError(e error) string {
	// D-Bus error details may contain connection settings; keep them out of task results.
	var value dbus.Error
	var pointer *dbus.Error
	var pathError *os.PathError
	var syntaxError *json.SyntaxError
	var typeError *json.UnmarshalTypeError
	if errors.As(e, &value) || errors.As(e, &pointer) || errors.As(e, &pathError) || errors.As(e, &syntaxError) || errors.As(e, &typeError) {
		return "NetworkManager operation failed; check the connection state"
	}
	return e.Error()
}
func RecoverNMServices(expected string) error {
	if expected != "" && !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(expected) {
		return fmt.Errorf("Invalid recovery request")
	}
	unlock, e := networkd.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	return recoverNMServicesLocked(expected, false)
}
func recoverNMServicesLocked(expected string, force bool) error {
	records := []*nmChange{}
	for _, path := range []string{wifiRecoveryPath, filepath.Join(sharingRoot, "pending.json")} {
		s, e := readNMChange(path)
		if e != nil {
			return e
		}
		if s != nil && (expected == "" || expected == s.ID) {
			records = append(records, s)
		}
	}
	if len(records) == 0 {
		return nil
	}
	a, e := connect()
	if e != nil {
		return e
	}
	defer a.bus.Close()
	boot, e := bootID()
	if e != nil {
		return e
	}
	for _, s := range records {
		if !supplementalKind(s.Kind) {
			return fmt.Errorf("Invalid network recovery state")
		}
		if s.Status == "confirmed" && strings.HasPrefix(s.Kind, "network.share.") {
			if e = a.cleanupNMConfirmed(s); e != nil {
				return e
			}
			continue
		}
		if !active(&s.state) {
			continue
		}
		if !force && expected == "" && strings.HasPrefix(s.Kind, "network.wifi.") && s.Boot == boot && s.Deadline > float64(time.Now().UnixNano())/1e9 {
			// Replace an older Python timer with the native worker without extending its deadline.
			if e = s.disarm(); e != nil {
				return e
			}
			if e = s.arm(int(math.Ceil(s.Deadline - float64(time.Now().UnixNano())/1e9))); e != nil {
				return e
			}
			continue
		}
		if strings.HasPrefix(s.Kind, "network.share.") {
			e = a.rollbackNMSharing(s)
		} else {
			e = a.rollbackWifi(s)
		}
		if e != nil {
			s.Status = "rollback-failed"
			s.Error = publicNMError(e)
			if persist := s.remember(); persist != nil {
				return persist
			}
			return e
		}
		s.Status = "expired"
		s.Error = ""
		if e = s.remember(); e != nil {
			return e
		}
		if e = s.disarm(); e != nil {
			return e
		}
	}
	return nil
}
func RunNMServices() error {
	if e := RecoverNMServices(""); e != nil {
		fmt.Fprintln(os.Stderr, "Network recovery requires attention")
	}
	a, e := connect()
	if e != nil {
		return e
	}
	defer a.bus.Close()
	first := true
	for {
		unlock, e := networkd.Lock()
		if e != nil {
			return e
		}
		e = func() error {
			groups, e := loadNMGroups()
			if e != nil {
				return e
			}
			if first {
				boot, e := bootID()
				if e != nil {
					return e
				}
				path := filepath.Join(sharingRoot, "boot")
				raw, e := os.ReadFile(path)
				if e != nil && !os.IsNotExist(e) {
					return e
				}
				if strings.TrimSpace(string(raw)) != boot {
					for i := range groups {
						if !groups[i].Autostart {
							groups[i].Enabled = false
						}
					}
					if e = storeNMGroups(groups); e != nil {
						return e
					}
					if e = nmWrite(path, boot, 0600); e != nil {
						return e
					}
				}
			}
			s, e := currentNMChange(true)
			if e != nil {
				return e
			}
			if s != nil && supplementalKind(s.Kind) {
				if e = a.currentNM(s); e != nil {
					return e
				}
			}
			groups, e = loadNMGroups()
			if e != nil {
				return e
			}
			if s == nil || !active(&s.state) {
				for _, g := range groups {
					if g.Enabled && (!first || g.Autostart) {
						if err := a.activateNMGroup(g, true); err != nil {
							fmt.Fprintln(os.Stderr, "Sharing route refresh failed")
						}
					}
				}
			}
			return nil
		}()
		unlock()
		if e != nil {
			return e
		}
		first = false
		time.Sleep(5 * time.Second)
	}
}
func RemoveNMServices() error {
	unlock, e := networkd.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	if e = recoverNMServicesLocked("", true); e != nil {
		return e
	}
	a, e := connect()
	if e != nil {
		return e
	}
	defer a.bus.Close()
	groups, preserved, e := removalNMGroups()
	if e != nil {
		return e
	}
	for _, g := range groups {
		if g.Enabled {
			if e = a.deactivateNMGroup(g); e != nil {
				return e
			}
		}
		ids := []string{}
		for _, id := range g.Profiles {
			ids = append(ids, id)
		}
		if e = a.deleteProfiles(ids); e != nil {
			return e
		}
	}
	if len(groups) > 0 {
		if e = writeNetworkJSON(filepath.Join(sharingRoot, "groups.json"), preserved); e != nil {
			return e
		}
	}
	snapshot, e := a.radioSnapshot()
	if e != nil {
		return e
	}
	for _, d := range snapshot.Devices {
		if d.Disabled {
			if e = a.configureRadio(d.Name, true); e != nil {
				return e
			}
		}
	}
	files, e := filepath.Glob(filepath.Join(wifiConfigRoot, "90-panasms-wifi-*.conf"))
	if e != nil {
		return e
	}
	for _, file := range files {
		if e = os.Remove(file); e != nil {
			return e
		}
	}
	return a.call(nmPath, nm+".Reload", uint32(1)).Err
}

func CheckServiceRemoval() error {
	for _, path := range []string{statePath, wifiRecoveryPath, filepath.Join(sharingRoot, "pending.json")} {
		raw, e := os.ReadFile(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		var s struct {
			Status string `json:"status"`
		}
		if e = json.Unmarshal(raw, &s); e != nil {
			return e
		}
		if s.Status == "applying" || s.Status == "pending" || s.Status == "rollback-failed" {
			return fmt.Errorf("Confirm or roll back pending network changes before package changes.")
		}
	}
	return nil
}

func removalNMGroups() ([]nmGroup, []json.RawMessage, error) {
	owned := []nmGroup{}
	preserved := []json.RawMessage{}
	raw, e := os.ReadFile(filepath.Join(sharingRoot, "groups.json"))
	if os.IsNotExist(e) {
		return owned, preserved, nil
	}
	if e != nil {
		return nil, nil, e
	}
	var records []json.RawMessage
	if e = json.Unmarshal(raw, &records); e != nil {
		return nil, nil, e
	}
	for _, record := range records {
		var identity struct {
			Provider string `json:"provider"`
		}
		if e = json.Unmarshal(record, &identity); e != nil {
			return nil, nil, e
		}
		if identity.Provider != "" && identity.Provider != "NetworkManager" {
			preserved = append(preserved, record)
			continue
		}
		var g nmGroup
		if e = json.Unmarshal(record, &g); e != nil {
			return nil, nil, e
		}
		owned = append(owned, g)
	}
	return owned, preserved, nil
}
