package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type interruptionMarker struct {
	Nonce     string `json:"nonce"`
	Phase     string `json:"phase"`
	PID       int    `json:"pid"`
	Committed bool   `json:"committed"`
}

func TestIsolatedModuleInterruptionChild(t *testing.T) {
	phase := os.Getenv("GO14_DEATH_PHASE")
	if phase == "" {
		t.Skip("only launched by isolated VM acceptance parent")
	}
	if !contains([]string{"staging", "gated", "reloaded", "base-started", "app-started", "committed"}, phase) {
		t.Fatal("unknown interruption phase")
	}
	s, _, _ := acceptanceGuard(t)
	nonce := os.Getenv("GO14_FIXTURE_NONCE")
	if !uploadToken.MatchString(nonce) {
		t.Fatal("missing fixture ownership nonce")
	}
	root, err := trustedDirectory(acceptanceRoot, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, err := readOwnedAt(root, ".owner", 0, 64)
	if err != nil || string(raw) != nonce {
		t.Fatal("fixture ownership proof refused", err)
	}
	ready := func() {
		state, err := s.loadTransaction()
		if err != nil || state == nil || state.Committed != (phase == "committed") {
			t.Fatal("unexpected transaction at death boundary", err)
		}
		marker, err := json.Marshal(interruptionMarker{nonce, phase, os.Getpid(), state.Committed})
		if err != nil {
			t.Fatal(err)
		}
		if err := atomicAt(root, "death-ready.json", marker, 0600, 0); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	actualRun := s.run
	s.run = func(ctx context.Context, argv []string, options systemops.CommandOptions) ([]byte, error) {
		if phase == "gated" && len(argv) == 4 && argv[1] == "disable" {
			ready()
		}
		raw, err := actualRun(ctx, argv, options)
		if err == nil {
			if phase == "reloaded" && len(argv) == 2 && argv[1] == "daemon-reload" {
				ready()
			}
			if len(argv) == 4 && argv[1] == "enable" && (phase == "base-started" && argv[3] == unit("go14-base") || phase == "app-started" && argv[3] == unit("go14-app")) {
				ready()
			}
		}
		return raw, err
	}
	actualMounts := s.mounts
	s.mounts = func() ([]string, error) {
		rows, err := actualMounts()
		if err == nil && phase == "committed" {
			state, readErr := s.loadTransaction()
			if readErr != nil {
				return nil, readErr
			}
			if state != nil && state.Committed {
				ready()
			}
		}
		return rows, err
	}
	checks := 0
	err = acceptanceExecute(t, s, "module.install", map[string]any{"upload": os.Getenv("GO14_DEATH_UPLOAD")}, func() error {
		checks++
		if phase == "staging" && checks == 4 {
			ready()
		}
		return nil
	})
	t.Fatal("interruption boundary was not reached", err)
}

func acceptanceInterruptions(t *testing.T, s lifecycle, server []byte, private ed25519.PrivateKey) {
	t.Helper()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	owner := hex.EncodeToString(nonce[:])
	root, err := trustedDirectory(acceptanceRoot, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := atomicAt(root, ".owner", []byte(owner), 0600, 0); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"staging", "gated", "reloaded", "base-started", "app-started", "committed"} {
		t.Run("SIGKILL-"+phase, func(t *testing.T) {
			before, err := s.registry()
			if err != nil {
				t.Fatal(err)
			}
			beforePayloads := map[string]directoryIdentity{}
			beforeUnits := map[string]fileSnapshot{}
			code, err := trustedDirectory(s.root, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer code.Close()
			units, err := trustedDirectory(s.units, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer units.Close()
			for _, id := range []string{"go14-base", "go14-app"} {
				beforePayloads[id], err = directoryAt(code, id, 0)
				if err != nil {
					t.Fatal(err)
				}
				beforeUnits[id], err = snapshotAt(units, unit(id), 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			params := acceptanceBundle(t, s, server, private, "1.1.1", "healthy")
			if err := unix.Unlinkat(int(root.Fd()), "death-ready.json", 0); err != nil && err != unix.ENOENT {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestIsolatedModuleInterruptionChild$", "-test.v")
			cmd.Env = append(os.Environ(), "GO14_DEATH_PHASE="+phase, "GO14_FIXTURE_NONCE="+owner, "GO14_DEATH_UPLOAD="+text(params, "upload"))
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
			if err != nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal("pidfd ownership unavailable", err)
			}
			defer unix.Close(pidfd)
			finished := make(chan error, 1)
			go func() { finished <- cmd.Wait() }()
			waited := false
			defer func() {
				if !waited {
					_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
					<-finished
				}
			}()
			deadline := time.Now().Add(30 * time.Second)
			var marker interruptionMarker
			for {
				select {
				case err := <-finished:
					waited = true
					t.Fatal("child exited before its real boundary", err, output.String())
				default:
				}
				raw, err := readOwnedAt(root, "death-ready.json", 0, 1024)
				if err == nil {
					if systemops.Decode(raw, &marker) != nil || marker.Nonce != owner || marker.Phase != phase || marker.PID != cmd.Process.Pid || marker.Committed != (phase == "committed") {
						t.Fatal("foreign interruption marker refused")
					}
					break
				}
				if !errors.Is(err, unix.ENOENT) || !time.Now().Before(deadline) {
					t.Fatal("interruption observation failed", err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil {
				t.Fatal(err)
			}
			waitErr := <-finished
			waited = true
			var exited *exec.ExitError
			if !errors.As(waitErr, &exited) || !exited.Sys().(syscall.WaitStatus).Signaled() || exited.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatal("child was not killed at the observed boundary", waitErr, output.String())
			}
			state, err := s.loadTransaction()
			if err != nil || state == nil || state.Committed != marker.Committed {
				t.Fatal("journal not retained after actual SIGKILL", err)
			}
			var servicePIDs []string
			if marker.Committed {
				for _, id := range []string{"go14-base", "go14-app"} {
					raw, err := s.run(context.Background(), []string{"systemctl", "show", "--property=MainPID", "--value", unit(id)}, systemops.CommandOptions{})
					if err != nil || strings.TrimSpace(string(raw)) == "0" {
						t.Fatal("committed fixture service unavailable", err)
					}
					servicePIDs = append(servicePIDs, string(raw))
				}
			}
			if err := s.recoverStartup(context.Background()); err != nil {
				t.Fatal("native startup recovery failed", err)
			}
			current, err := s.registry()
			expected := before
			if marker.Committed {
				expected = state.After
				for index, id := range []string{"go14-base", "go14-app"} {
					raw, err := s.run(context.Background(), []string{"systemctl", "show", "--property=MainPID", "--value", unit(id)}, systemops.CommandOptions{})
					if err != nil || string(raw) != servicePIDs[index] {
						t.Fatal("committed cleanup restarted a service", err)
					}
				}
			}
			if err != nil || !registryEqual(current, expected) {
				t.Fatal("recovery registry/identity mismatch", err)
			}
			for _, id := range []string{"go14-base", "go14-app"} {
				identity, err := directoryAt(code, id, 0)
				expectedPayload, expectedUnit := beforePayloads[id], beforeUnits[id]
				if marker.Committed {
					expectedPayload, expectedUnit = state.Payloads[id].Staged, state.Candidates[id]
				}
				if err != nil || identity != expectedPayload {
					t.Fatal("recovered code incarnation mismatch", id, err)
				}
				actualUnit, err := snapshotAt(units, unit(id), 0)
				if err != nil || !snapshotEqual(actualUnit, expectedUnit) {
					t.Fatal("recovered unit bytes/metadata mismatch", id, err)
				}
				raw, err := os.ReadFile(filepath.Join(s.root, id, "backend/revision"))
				if err != nil || string(raw) != "healthy" {
					t.Fatal("recovery payload mismatch", id, err)
				}
				if err := requireIdle(context.Background(), current[id], s.health, s.run); err != nil {
					t.Fatal("restored module unavailable", id, err)
				}
				version, err := os.ReadFile(filepath.Join(s.root, id, "backend/version"))
				if err != nil || string(version) != text(expected[id], "version") {
					t.Fatal("recovered payload version differs from registry", id, err)
				}
			}
			data, err := os.ReadFile(acceptanceRoot + "/data/go14-app/retained")
			if err != nil || string(data) != "retained module data" {
				t.Fatal("interrupted lifecycle changed module data", err)
			}
			if pending, err := s.loadTransaction(); err != nil || pending != nil {
				t.Fatal("recovery journal remains", err)
			}
			t.Log("PASS actual pidfd SIGKILL and retained-journal recovery:", phase)
		})
		if t.Failed() {
			t.Fatal("remaining mutation cases stopped; owner snapshot restore required")
		}
	}
}
