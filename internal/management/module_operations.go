package management

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/modules"
	"panasms.local/backend/internal/systemops"
)

var memberModuleActions = map[string]bool{"file.git-switch": true, "file.mkdir": true, "file.copy": true, "file.move": true, "file.rename": true, "file.trash": true, "file.restore": true, "file.delete": true}

// ModuleHandler runs only native extensions; core handlers remain separately
// routed, and a native failure can never retry through the Python dispatcher.
func ModuleHandler(core systemops.Handler, authorize func(string) (auth.Identity, error), changing func() (bool, error)) systemops.Handler {
	return moduleHandler(core, authorize, changing, 0)
}

func moduleHandler(core systemops.Handler, authorize func(string) (auth.Identity, error), changing func() (bool, error), trustedUID uint32) systemops.Handler {
	return func(mode systemops.Mode, user string, req *systemops.Request, r *systemops.Reporter) (result json.RawMessage, err error) {
		kind, name := "actions", req.Action
		if mode == systemops.ModeQuery {
			kind, name = "queries", req.View
		}
		if reservedModuleRoute(kind, name) {
			return core(mode, user, req, r)
		}
		mutated := false
		defer func() {
			if err != nil && !mutated {
				err = systemops.BeforeMutation(err)
			}
		}()
		deny := func(s string) error { return &systemops.Rejected{Message: s} }
		id, err := authorize(user)
		if err != nil {
			return nil, err
		}
		if req.Actor != nil && (req.Actor.UID != id.UID || req.Actor.Epoch != id.Epoch || req.Actor.Principal != id.Principal) {
			return nil, deny("Account identity or access has changed; request a new operation plan")
		}
		if id.Role != "admin" && !(mode == systemops.ModeQuery && req.View == "files") && !(mode != systemops.ModeQuery && memberModuleActions[req.Action]) {
			return nil, deny("Administrator permissions required")
		}
		if mode == systemops.ModeRecover {
			if req.Params == nil {
				return nil, deny("Parameters must be an object")
			}
			return moduleRecovery(req, user, id.UID, id.Role == "admin")
		}
		if mode == systemops.ModeExecute {
			r.Cancellable(true)
			defer r.Cancellable(false)
		}
		lock, err := moduleLock(r, trustedUID)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		m, err := modules.Operation(kind, name, reservedModuleRoute)
		if err != nil {
			return nil, err
		}
		if m == nil || !m.Enabled || m.Operations == "" {
			return nil, deny("Module is not installed or is disabled")
		}
		executable, err := modules.VerifyOperation(m, trustedUID)
		if err != nil {
			return nil, err
		}
		defer executable.Close()
		if mode == systemops.ModeQuery {
			return invokeModule(executable, "query", user, map[string]any{"target": req.Target})
		}
		if req.Params == nil {
			return nil, deny("Parameters must be an object")
		}
		checkChanging := func() error {
			active, e := changing()
			if e != nil {
				return e
			}
			if active {
				return deny("A system update is in progress; wait for the panel to reconnect")
			}
			return nil
		}
		if err = checkChanging(); err != nil {
			return nil, err
		}
		if mode == systemops.ModeExecute {
			r.Cancellable(true)
			defer r.Cancellable(false)
			if err = r.Checkpoint(); err != nil {
				return nil, err
			}
		}
		body := map[string]any{"action": req.Action, "params": req.Params}
		raw, err := invokeModule(executable, "plan", user, body)
		if err != nil {
			return nil, err
		}
		var plan map[string]any
		if err = systemops.Decode(raw, &plan); err != nil {
			return nil, err
		}
		fingerprint, ok := plan["fingerprint"].(string)
		if !ok || fingerprint == "" {
			return nil, deny("Invalid module operation plan")
		}
		confirmation, ok := plan["confirmation"].(string)
		if !ok {
			return nil, deny("Invalid module operation plan")
		}
		sum := sha256.Sum256([]byte(m.ID + "\x00" + m.Installation + "\x00" + m.Version + "\x00" + m.Files["bin/server"] + "\x00" + fingerprint))
		plan["fingerprint"] = hex.EncodeToString(sum[:])
		if mode == systemops.ModePlan {
			return json.Marshal(plan)
		}
		if mode != systemops.ModeExecute {
			return nil, deny("Unknown operation mode")
		}
		if req.Fingerprint != plan["fingerprint"] {
			return nil, deny("State has changed. Review a new operation plan.")
		}
		if req.Confirmation != confirmation {
			return nil, deny("The exact operation target was not confirmed")
		}
		fresh, err := authorize(user)
		if err != nil {
			return nil, err
		}
		if fresh != id {
			return nil, deny("Account identity or access has changed; request a new operation plan")
		}
		if err = checkChanging(); err != nil {
			return nil, err
		}
		freshExecutable, e := modules.VerifyOperation(m, trustedUID)
		if e != nil {
			return nil, e
		}
		defer freshExecutable.Close()
		r.Cancellable(false)
		if err = r.Checkpoint(); err != nil {
			return nil, err
		}
		mutated = true
		return invokeModule(freshExecutable, "execute", user, body)
	}
}

func invokeModule(executable *os.File, mode, user string, body any) (json.RawMessage, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("/proc/self/fd/3", "operations", mode, user)
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = os.Environ()
	if mode == "execute" {
		cmd.Env = append(cmd.Env, "PANASMS_OPERATION=1")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if value := os.Getenv(systemops.ControlFDEnv); value != "" {
		fd, e := strconv.Atoi(value)
		if e != nil || fd < 3 {
			return nil, fmt.Errorf("invalid cancellation descriptor")
		}
		copyFD, e := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
		if e != nil {
			return nil, e
		}
		control := os.NewFile(uintptr(copyFD), "module control")
		defer control.Close()
		cmd.ExtraFiles = []*os.File{control}
		cmd.Env = append(cmd.Env, systemops.ControlFDEnv+"=3")
	}
	cmd.Path = fmt.Sprintf("/proc/self/fd/%d", 3+len(cmd.ExtraFiles))
	cmd.Args[0] = cmd.Path
	cmd.ExtraFiles = append(cmd.ExtraFiles, executable)
	output := limitedOutput{limit: systemops.MaxOutput}
	cmd.Stdout = &output
	cmd.Stderr = &moduleProgress{out: os.Stderr}
	if err = cmd.Run(); err != nil {
		return nil, fmt.Errorf("native module worker failed: %w", err)
	}
	if output.overflow {
		return nil, fmt.Errorf("native module response too large")
	}
	var result map[string]json.RawMessage
	if err = systemops.Decode(output.Bytes(), &result); err != nil || result == nil {
		return nil, fmt.Errorf("invalid native module response")
	}
	var status systemops.Result
	if err = systemops.Decode(output.Bytes(), &status); err != nil {
		return nil, err
	}
	if status.Cancelled {
		return nil, systemops.ErrCancelled
	}
	if status.Error != "" {
		return nil, &systemops.Rejected{Message: status.Error}
	}
	return output.Bytes(), nil
}

// Oversized progress lines are discarded while the worker is drained; stopping
// the read could deadlock a mutation that is still completing.
type moduleProgress struct {
	out     io.Writer
	line    []byte
	discard bool
}

func (p *moduleProgress) Write(raw []byte) (int, error) {
	size := len(raw)
	for _, b := range raw {
		if b == '\n' {
			if !p.discard {
				if _, err := p.out.Write(append(p.line, '\n')); err != nil {
					return 0, err
				}
			}
			p.line = p.line[:0]
			p.discard = false
		} else if !p.discard {
			if len(p.line) >= systemops.MaxProgressLine-1 {
				p.line = p.line[:0]
				p.discard = true
			} else {
				p.line = append(p.line, b)
			}
		}
	}
	return size, nil
}

func moduleLock(r *systemops.Reporter, trustedUID uint32) (*os.File, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if err := r.Checkpoint(); err != nil {
			return nil, err
		}
		lock, err := modules.Lock(trustedUID)
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return lock, err
		}
		if !time.Now().Before(deadline) {
			return nil, &systemops.Rejected{Message: "Module maintenance in progress; retry shortly"}
		}
		time.Sleep(25 * time.Millisecond)
	}
}
