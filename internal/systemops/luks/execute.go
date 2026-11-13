package luks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/disksleep"
	"panasms.local/backend/internal/systemops/storagebase"
)

func Execute(ctx context.Context, action string, params map[string]any, expected, actor string, authorize func() error, r *systemops.Reporter) (json.RawMessage, error) {
	domain, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	defer domain.Close()
	var result json.RawMessage
	started := false
	err = disksleep.WithStorageLock(func() error {
		target, err := canonicalTarget(params)
		if err != nil {
			return err
		}
		lock, err := storagebase.DeviceLock(ctx, target)
		if err != nil {
			return err
		}
		defer lock.Close()
		p, err := prepare(ctx, action, params)
		if err != nil {
			return err
		}
		defer func() {
			if p.pin != nil {
				p.pin.Close()
			}
		}()
		if target != p.Target || expected == "" || expected != p.fingerprint {
			return reject("State has changed. Review a new operation plan.")
		}
		if authorize == nil {
			return reject("Account authorization is unavailable")
		}
		if err = authorize(); err != nil {
			return err
		}
		if err = p.pin.Verify(); err != nil {
			return err
		}
		if r != nil {
			if err = r.Checkpoint(); err != nil {
				return err
			}
			r.Cancellable(false)
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		p.Actor = actor
		started = true
		var value map[string]any
		switch action {
		case "luks.create", "luks.open", "luks.close":
			value, err = applyBasic(ctx, action, params, p, r)
		default:
			value, err = executeExtra(ctx, action, params, p, p.ReadPath, r)
		}
		if err != nil {
			return err
		}
		result, err = json.Marshal(value)
		return err
	})
	if err != nil && !started {
		return nil, systemops.BeforeMutation(err)
	}
	return result, err
}

func applyBasic(ctx context.Context, action string, params map[string]any, p *prepared, r *systemops.Reporter) (map[string]any, error) {
	opts := systemops.CommandOptions{Operation: true, Reporter: r, Timeout: 5 * time.Minute}
	var args []string
	switch action {
	case "luks.create", "luks.open":
		password, err := passphrase(params, "passphrase")
		if err != nil {
			return nil, err
		}
		opts.Input = []byte(password)
		defer clear(opts.Input)
		if action == "luks.create" {
			args = []string{"cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--key-file", "-", p.ReadPath}
		} else {
			args = []string{"cryptsetup", "open", "--type", "luks", "--key-file", "-", p.ReadPath, p.Name}
		}
	case "luks.close":
		// Closing a mapper requires its open count to reach zero. Drop our
		// verification descriptor before asking device-mapper to deactivate it.
		if err := p.pin.Close(); err != nil {
			return nil, err
		}
		identity := p.pin.Identity
		p.pin = nil
		// A privileged external mapper operation can race the advisory locks.
		// Recheck the kernel incarnation and dm identity after dropping the fd.
		sys := filepath.Join("/sys/class/block", filepath.Base(p.Target))
		for leaf, expected := range map[string]string{"dev": identity.DeviceNumber, "diskseq": identity.DiskSequence, "dm/uuid": p.MappingUUID, "dm/name": p.Name} {
			raw, err := os.ReadFile(filepath.Join(sys, leaf))
			if err != nil || strings.TrimSpace(string(raw)) != expected {
				return nil, systemops.BeforeMutation(reject("The encrypted mapping changed. Review a new operation plan."))
			}
		}
		args = []string{"cryptsetup", "close", "--", p.Name}
	}
	if _, err := systemops.Command(ctx, args, opts); err != nil {
		if code, ok := systemops.CommandExitCode(err); ok {
			switch {
			case action == "luks.open" && code == 2:
				return nil, reject("The LUKS password did not unlock this volume")
			case code == 5:
				return nil, reject("The encrypted volume or mapping is busy")
			}
		}
		return nil, err
	}
	if _, err := systemops.Command(context.WithoutCancel(ctx), []string{"udevadm", "settle", "--timeout=30"}, systemops.CommandOptions{}); err != nil {
		return nil, err
	}
	return map[string]any{"target": p.Target, "message": "Operation complete. Background synchronization or SMART testing is shown in device status."}, nil
}
