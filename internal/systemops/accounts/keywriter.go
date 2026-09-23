package accounts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// KeyRequest is the JSON body the key writer consumes on stdin, matching the
// profile-keys.py body: {"action": "list"|"add"|"delete", "key": ..., "id": ...}.
type KeyRequest struct {
	Action string `json:"action"`
	Key    string `json:"key"`
	ID     string `json:"id"`
}

// errKeyOp is the single opaque error the key writer surfaces, matching
// profile-keys.py's uniform "SSH key operation failed" on any OSError/ValueError
// so a caller learns nothing about another user's home layout.
var errKeyOp = errors.New("SSH key operation failed")

// ManageKeys performs a list/add/delete on home/.ssh/authorized_keys. It MUST
// run in a process that has already dropped to the target user's identity
// (initgroups/setgid/setuid), exactly like profile-keys.py's __main__ — this
// function does no privilege handling itself. It reproduces manage() line for
// line: open .ssh with O_NOFOLLOW, flock it exclusively, read the existing file
// through an O_NOFOLLOW descriptor relative to that directory, apply the action,
// then write to a fresh O_EXCL temp and atomically rename it into place with an
// fsync of the directory.
func ManageKeys(home string, req KeyRequest) ([]Key, error) {
	sshDir := filepath.Join(home, ".ssh")
	if _, err := os.Lstat(sshDir); err != nil {
		if !os.IsNotExist(err) {
			return nil, errKeyOp
		}
		if req.Action == "list" {
			return []Key{}, nil
		}
		if err := os.Mkdir(sshDir, 0o700); err != nil {
			return nil, errKeyOp
		}
	}

	dirFD, err := unix.Open(sshDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errKeyOp
	}
	defer unix.Close(dirFD)
	if err := unix.Flock(dirFD, unix.LOCK_EX); err != nil {
		return nil, errKeyOp
	}

	text, err := readAt(dirFD, "authorized_keys")
	if err != nil {
		return nil, err
	}
	lines := splitLines(text)

	switch req.Action {
	case "list":
		return parseKeys(lines), nil
	case "add":
		lines, err = addKey(lines, req.Key)
	case "delete":
		lines, err = deleteKey(lines, req.ID)
	default:
		return nil, errKeyOp
	}
	if err != nil {
		return nil, err
	}

	if err := writeAt(dirFD, lines); err != nil {
		return nil, err
	}
	return parseKeys(lines), nil
}

// readAt reads a file relative to dirFD through an O_NOFOLLOW descriptor,
// enforcing the same 128 KiB+1 cap profile-keys.py uses (a longer file is a
// hard error). A missing file yields empty text.
func readAt(dirFD int, name string) (string, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return "", nil
		}
		return "", errKeyOp
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", errKeyOp
	}
	buf, err := io.ReadAll(io.LimitReader(f, 131073))
	if err != nil || len(buf) > 131072 {
		return "", errKeyOp
	}
	return string(buf), nil
}

// writeAt writes lines to a fresh O_EXCL temp file relative to dirFD, fsyncs it,
// renames it onto authorized_keys and fsyncs the directory, matching manage()'s
// atomic replace. The temp name is always unlinked on the way out.
func writeAt(dirFD int, lines []string) (err error) {
	suffix := make([]byte, 8)
	if _, e := rand.Read(suffix); e != nil {
		return errKeyOp
	}
	name := ".authorized_keys-" + hex.EncodeToString(suffix)
	fd, e := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if e != nil {
		return errKeyOp
	}
	defer func() {
		if unlinkErr := unix.Unlinkat(dirFD, name, 0); unlinkErr != nil && err == nil {
			// A leftover temp on the happy path (already renamed) is ENOENT and
			// harmless; only surface a real failure when nothing else did.
			if unlinkErr != unix.ENOENT {
				err = errKeyOp
			}
		}
	}()
	f := os.NewFile(uintptr(fd), name)
	content := strings.Join(lines, "\n") + "\n"
	if _, e := f.WriteString(content); e != nil {
		f.Close()
		return errKeyOp
	}
	if e := f.Sync(); e != nil {
		f.Close()
		return errKeyOp
	}
	if e := f.Close(); e != nil {
		return errKeyOp
	}
	if e := unix.Renameat(dirFD, name, dirFD, "authorized_keys"); e != nil {
		return errKeyOp
	}
	if e := unix.Fsync(dirFD); e != nil {
		return errKeyOp
	}
	return nil
}

// addKey validates and appends a public key, reproducing manage()'s add path:
// the trimmed line must have no CR/LF, be at most 16384 bytes, match the allowed
// algorithm prefix, pass `ssh-keygen -l`, and not duplicate an existing key by
// fingerprint.
func addKey(lines []string, key string) ([]string, error) {
	line := strings.TrimSpace(key)
	if strings.ContainsAny(line, "\n\r") || len(line) > 16384 || !addKeyPattern.MatchString(line) {
		return nil, errors.New("Expected one OpenSSH public key without options")
	}
	if err := verifyKey(line); err != nil {
		return nil, err
	}
	item, ok := KeyInfo(line)
	if !ok {
		return nil, errors.New("Invalid public key")
	}
	for _, existing := range lines {
		if k, ok := KeyInfo(existing); ok && k.Fingerprint == item.Fingerprint {
			return nil, errors.New("Key already exists")
		}
	}
	return append(lines, line), nil
}

// deleteKey removes the line whose id (sha256 hex of the line) matches, matching
// manage()'s delete path; removing nothing is an error.
func deleteKey(lines []string, id string) ([]string, error) {
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if keyID(line) != id {
			kept = append(kept, line)
		}
	}
	if len(kept) == len(lines) {
		return nil, errors.New("Key not found")
	}
	return kept, nil
}

// verifyKey runs `ssh-keygen -l -f <tempfile>` over the single line, matching
// manage()'s validation, and rejects on a non-zero exit.
func verifyKey(line string) error {
	tmp, err := os.CreateTemp("", "panasms-key-")
	if err != nil {
		return errKeyOp
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(line + "\n"); err != nil {
		tmp.Close()
		return errKeyOp
	}
	tmp.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/ssh-keygen", "-l", "-f", tmp.Name())
	if err := cmd.Run(); err != nil {
		return errors.New("Invalid public key")
	}
	return nil
}

// splitLines splits authorized_keys text into lines, matching Python's
// str.splitlines(): a line boundary is a "\n" or "\r\n", and a single trailing
// newline does not yield a final empty element — but an interior or repeated
// blank line is preserved ("a\n\n" -> ["a", ""]), so we strip at most one
// trailing empty produced by the final newline rather than a whole run.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	if strings.HasSuffix(normalized, "\n") {
		normalized = normalized[:len(normalized)-1]
	}
	return strings.Split(normalized, "\n")
}
