package oled

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

func commandOutput(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s: %w: %s", name, e, raw)
	}
	return string(raw), nil
}
func Run(ctx context.Context) error {
	cfg, e := readConfig(ConfigPath)
	if e != nil {
		return e
	}
	if !cfg.Enabled {
		return nil
	}
	if e = os.MkdirAll("/run/panasms-oled", 0755); e != nil {
		return e
	}
	var device *Device
	defer func() {
		if device != nil {
			device.Close()
		}
		_ = os.Remove(StatusPath)
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		status := Status{ObservedAt: time.Now().UTC(), Applied: cfg, Lines: []string{}}
		if device == nil {
			e = prepare(ctx, cfg)
			if e == nil {
				device, e = Open(cfg)
			}
		}
		if e == nil {
			status.Lines = Readings(cfg)
			e = device.Display(Render(status.Lines, cfg.Rotation, int(time.Now().Unix()/60%2)))
		}
		if e != nil {
			status.Error = e.Error()
			if device != nil {
				device.Close()
				device = nil
			}
		}
		if err := atomicJSON(StatusPath, status); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
