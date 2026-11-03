package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PaNasMs/module-sdk/maintenance"
	"github.com/PaNasMs/module-sdk/modulehost"
	"github.com/PaNasMs/module-sdk/modules"
)

func main() {
	executable, err := os.Executable()
	if err != nil {
		panic(err)
	}
	code := filepath.Dir(filepath.Dir(executable))
	modules.Root = filepath.Dir(code)
	if modules.Root != "/var/lib/panasms-go14-acceptance/modules" {
		panic("fixture installation path refused")
	}
	id := filepath.Base(code)
	if id != "go14-base" && id != "go14-app" {
		panic("fixture module identity refused")
	}
	behavior, err := os.ReadFile(filepath.Join(code, "backend/revision"))
	if err != nil {
		panic(err)
	}
	if strings.TrimSpace(string(behavior)) == "fail-start" {
		os.Exit(17)
	}
	data := filepath.Join(filepath.Dir(modules.Root), "data", id)
	var active atomic.Int32
	go func() {
		for {
			time.Sleep(20 * time.Millisecond)
			if _, err := os.Stat(filepath.Join(data, "armed")); err != nil {
				continue
			}
			release, err := maintenance.Acquire()
			if err != nil {
				if err := os.WriteFile(filepath.Join(data, "blocked"), []byte("SDK maintenance denied"), 0600); err != nil {
					panic(err)
				}
				continue
			}
			active.Add(1)
			if err := os.WriteFile(filepath.Join(data, "running"), []byte("SDK shared lease acquired"), 0600); err != nil {
				panic(err)
			}
			for {
				if _, err := os.Stat(filepath.Join(data, "hold")); os.IsNotExist(err) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			_ = os.Remove(filepath.Join(data, "armed"))
			active.Add(-1)
			release()
		}
	}()
	modulehost.ServeWithActivity(id, active.Load, func(map[string]bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})
}
