package systemops

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// baseEnv is the minimal environment shared by command invocations. Locale and
// frontend variables are added per call. PATH is preserved so tools resolve.
func baseEnv() []string {
	env := []string{}
	if path := os.Getenv("PATH"); path != "" {
		env = append(env, "PATH="+path)
	}
	return env
}

// killGroup terminates the child's whole process group, escalating SIGTERM to
// SIGKILL after a 5-second grace period, then reaps it. It reproduces the
// cleanup in job_control.copying so a cancelled staging copy leaves no orphans.
func killGroup(cmd *exec.Cmd, done <-chan error) {
	pid := cmd.Process.Pid
	// Negative pid signals the process group created by Setpgid.
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-done:
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		return
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-done
	}
}
