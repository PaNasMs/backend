package networknative

import (
	"fmt"
	"os"
	"time"

	"panasms.local/backend/internal/maintenance"
	"panasms.local/backend/internal/systemops/networkd"
)

func Service() error {
	if e := Recover(false); e != nil {
		return e
	}
	for {
		if e := reconcile(); e != nil {
			fmt.Fprintln(os.Stderr, "Native network recovery:", e)
		}
		time.Sleep(5 * time.Second)
	}
}
func reconcile() error {
	release, e := maintenance.AcquirePath("/run/lock/panasms-maintenance.lock")
	if e != nil {
		return e
	}
	defer release()
	if e := Recover(false); e != nil {
		return e
	}
	unlock, e := networkd.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	var current struct {
		Status string `json:"status"`
	}
	if e = read(pending, &current); e != nil && !os.IsNotExist(e) {
		return e
	}
	if current.Status == "pending" || current.Status == "applying" || current.Status == "rollback-failed" {
		return nil
	}
	groups, e := Groups()
	if e != nil {
		return e
	}
	var lastBoot string
	_ = read(root+"/boot.json", &lastBoot)
	first := lastBoot != boot()
	if e = initializeWifi(groups, first); e != nil {
		return e
	}
	for i := range groups {
		g := &groups[i]
		if g.Provider != "networkd" {
			continue
		}
		if first && !g.Autostart {
			if g.Enabled {
				if e = DeactivateGroup(*g); e != nil {
					return e
				}
			}
			g.Enabled = false
		}
		if !g.Enabled {
			continue
		}
		if first || !exists("/sys/class/net/"+g.Bridge) {
			if e = ActivateGroup(*g); e != nil {
				return e
			}
		} else {
			for name, c := range g.Wifi {
				if !exists("/sys/class/net/" + name) {
					continue
				}
				config, err := wifiSettings(name)
				if err != nil {
					return err
				}
				if !config.Enabled {
					continue
				}
				if exists("/sys/class/net/"+name) && Identity(name) == g.Identities[name] && !APActive(name) {
					if e = StartAP(name, g.Bridge, c); e != nil {
						return e
					}
				}
			}
			if e = Routing(*g); e != nil {
				return e
			}
		}
	}
	if first {
		if e = write(groupsPath, groups); e != nil {
			return e
		}
		return write(root+"/boot.json", boot())
	}
	return nil
}
