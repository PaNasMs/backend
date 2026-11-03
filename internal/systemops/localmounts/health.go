package localmounts

import (
	"context"
	"encoding/json"
	"os"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"time"
)

func (s *service) checkFilesystem(ctx context.Context, source, fs string, repair bool, r *systemops.Reporter) (bool, string) {
	if !s.checkAvailable(fs) {
		return false, "Checking and repair are not yet available for this file system"
	}
	tool := checkers[fs]
	flags := []string{"-n"}
	if tool == "e2fsck" {
		flags = []string{"-f", "-n"}
	}
	accepted := []int{0}
	if repair {
		flags = []string{"-p"}
		if fs == "vfat" {
			flags = []string{"-a"}
		}
		accepted = []int{0, 1}
	}
	if r != nil {
		if repair {
			r.Stage("Repairing file system")
		} else {
			r.Stage("Checking file system without changes")
		}
	}
	args := append([]string{tool}, flags...)
	args = append(args, source)
	_, err := s.run(ctx, args, systemops.CommandOptions{Accepted: accepted, Timeout: time.Hour, Operation: repair, Reporter: r})
	if err != nil {
		prefix := "The file system failed its check. "
		if repair {
			prefix = "Errors remain after repair. "
		}
		return false, prefix + err.Error()
	}
	if repair {
		return s.checkFilesystem(ctx, source, fs, false, r)
	}
	return true, ""
}

type healthState struct {
	Identity        string  `json:"identity"`
	Status          string  `json:"status"`
	Reason          string  `json:"reason"`
	RepairAvailable bool    `json:"repairAvailable"`
	CheckedAt       float64 `json:"checkedAt"`
}

func saveHealth(root string, owner int, device storagequery.DeviceIdentity, clean bool, reason string, repair bool) error {
	status := "errors"
	if clean {
		status = "clean"
	}
	data, err := json.Marshal(healthState{device.DiskSequence + ":" + device.DeviceNumber, status, reason, repair, float64(time.Now().UnixNano()) / 1e9})
	if err != nil {
		return err
	}
	if err = storagebase.SecureDirectory(root, owner, true); err != nil {
		return err
	}
	target := filepath.Join(root, filepath.Base(device.Path)+".json")
	// Legacy readers accept the atomic replacement and the same diskseq:dev key.
	if st, err := os.Lstat(target); err == nil {
		if !st.Mode().IsRegular() {
			return reject("File system health state is unsafe")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(root, ".health-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(f.Name(), target); err != nil {
		return err
	}
	return syncDirectory(root)
}
