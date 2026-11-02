package management

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"panasms.local/backend/internal/systemops"
)

func moduleRecovery(req *systemops.Request, username string, expectedUID int, admin bool) (json.RawMessage, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	cmd := moduleRecoveryCommand(path, raw)
	if !admin {
		account, err := user.Lookup(username)
		if err != nil {
			return nil, err
		}
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil || uid == 0 || uid != uint64(expectedUID) {
			return nil, fmt.Errorf("invalid user")
		}
		gid, err := strconv.ParseUint(account.Gid, 10, 32)
		if err != nil {
			return nil, err
		}
		groups, err := account.GroupIds()
		if err != nil {
			return nil, err
		}
		ids := []uint32{}
		for _, group := range groups {
			n, e := strconv.ParseUint(group, 10, 32)
			if e != nil {
				return nil, e
			}
			ids = append(ids, uint32(n))
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: ids}, Pdeathsig: syscall.SIGTERM}
	}
	output := limitedOutput{limit: systemops.MaxOutput}
	cmd.Stdout = &output
	if err = cmd.Run(); err != nil {
		return nil, err
	}
	if output.overflow {
		return nil, fmt.Errorf("recovery output too large")
	}
	return output.Bytes(), nil
}

// InspectModuleRecovery runs in an isolated process with the actor's credentials.
// It observes retained state and never replays a module operation.
func InspectModuleRecovery(in io.Reader, out io.Writer) error {
	req, err := systemops.ReadRequest(in)
	if err != nil {
		return err
	}
	checks := []map[string]string{}
	route := "/"
	message := "No automatic recovery inspector is registered for this module action. Open the module and inspect its state before retrying. The operation has not been repeated."
	if strings.HasPrefix(req.Action, "file.") {
		route = "/files"
		for _, key := range []string{"target", "destination"} {
			value, ok := req.Params[key].(string)
			if !ok || !filepath.IsAbs(value) {
				continue
			}
			info, e := os.Lstat(value)
			if os.IsNotExist(e) {
				checks = append(checks, map[string]string{"label": key, "value": value + ": absent"})
			} else if e != nil {
				checks = append(checks, map[string]string{"label": key, "value": value + ": not inspectable"})
			} else {
				checks = append(checks, map[string]string{"label": key, "value": fmt.Sprintf("%s: present, %d bytes", value, info.Size())})
			}
		}
		destination, _ := req.Params["destination"].(string)
		target, _ := req.Params["target"].(string)
		if filepath.IsAbs(destination) {
			directory, e := os.Open(filepath.Dir(destination))
			if e != nil && !os.IsNotExist(e) {
				checks = append(checks, map[string]string{"label": "destination folder", "value": filepath.Dir(destination) + ": not inspectable"})
			}
			if directory != nil {
				defer directory.Close()
				found := 0
				for found < 50 {
					entries, e := directory.ReadDir(64)
					if e != nil && e != io.EOF {
						checks = append(checks, map[string]string{"label": "destination folder", "value": directory.Name() + ": not inspectable"})
						break
					}
					for _, entry := range entries {
						if found >= 50 {
							break
						}
						if !strings.HasPrefix(entry.Name(), ".panasms-copy-") {
							continue
						}
						found++
						if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
							continue
						}
						holder := filepath.Join(directory.Name(), entry.Name())
						journal := filepath.Join(holder, "transfer.json")
						info, e := os.Lstat(journal)
						if e != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
							continue
						}
						fd, e := unix.Open(journal, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
						if e != nil {
							continue
						}
						f := os.NewFile(uintptr(fd), "transfer journal")
						opened, e := f.Stat()
						if e != nil || !opened.Mode().IsRegular() {
							f.Close()
							continue
						}
						raw, e := io.ReadAll(io.LimitReader(f, 16385))
						f.Close()
						if e != nil || len(raw) > 16384 {
							continue
						}
						var state map[string]any
						if json.Unmarshal(raw, &state) != nil {
							continue
						}
						if state["destination"] == destination && state["source"] == target {
							phase, _ := state["phase"].(string)
							if phase == "" {
								phase = "unknown"
							}
							checks = append(checks, map[string]string{"label": "Retained transfer journal", "value": holder + ": " + phase})
						}
					}
					if e == io.EOF {
						break
					}
				}
			}
		}
		message = "Compare source and destination before retrying. A partial copy may exist; do not delete either automatically. Presence or size alone does not prove a complete copy."
		switch req.Action {
		case "file.trash":
			message = "Check Trash and the original folder. A missing source alone does not prove the item reached Trash."
		case "file.mkdir":
			message = "Check whether the intended folder exists before creating it again."
		case "file.permissions":
			message = "Review current ownership and permissions before applying another change."
		}
	}
	return systemops.WriteResult(out, map[string]any{"message": message, "checks": checks, "route": route, "recoveryAction": nil})
}

func moduleRecoveryCommand(path string, raw []byte) *exec.Cmd {
	cmd := exec.Command(path, "module-recovery-inspect")
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	return cmd
}
