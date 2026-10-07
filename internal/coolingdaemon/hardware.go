package coolingdaemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	gpio "github.com/warthog618/go-gpiocdev"
	"panasms.local/backend/internal/cooling"
)

const helperDir = "/usr/lib/panasms-cooling"
const markerPath = "/run/panasms-cooling/hardware.json"

type Wiring struct {
	Mode    string `json:"hardwareMode"`
	Control int    `json:"controlGPIO"`
	Tach    *int   `json:"tachGPIO"`
}

func wiring(s cooling.Settings) Wiring { return Wiring{s.HardwareMode, s.ControlGPIO, s.TachGPIO} }
func (w Wiring) same(other Wiring) bool {
	return w.Mode == other.Mode && w.Control == other.Control && (w.Tach == nil && other.Tach == nil || w.Tach != nil && other.Tach != nil && *w.Tach == *other.Tach)
}

var pwmPins = map[int]struct {
	channel  int
	function string
}{12: {0, "a0"}, 13: {1, "a0"}, 18: {2, "a3"}, 19: {3, "a3"}}

func command(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(name), err, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
func pinctrl(args ...string) ([]byte, error) {
	return command(filepath.Join(helperDir, "pinctrl"), args...)
}
func pwmChip(load bool) (string, error) {
	find := func() string {
		paths, _ := filepath.Glob("/sys/class/pwm/pwmchip*")
		for _, p := range paths {
			resolved, _ := filepath.EvalSymlinks(p)
			if strings.Contains(resolved, "/1f00098000.pwm/") {
				return p
			}
		}
		return ""
	}
	if p := find(); p != "" {
		return p, nil
	}
	if load {
		if _, err := command(filepath.Join(helperDir, "dtoverlay"), filepath.Join(helperDir, "pwm-enable.dtbo")); err != nil {
			return "", err
		}
		for i := 0; i < 20; i++ {
			if p := find(); p != "" {
				return p, nil
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	return "", fmt.Errorf("RP1 PWM0 controller is unavailable")
}
func Failsafe() error { return failsafe(nil) }
func failsafe(control *gpio.Line) error {
	raw, err := os.ReadFile(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var w Wiring
	if err = json.Unmarshal(raw, &w); err != nil {
		return err
	}
	s := cooling.Settings{CPUProfile: "balanced", Profile: "balanced", SampleSeconds: 60, HardwareMode: w.Mode, ControlGPIO: w.Control, TachGPIO: w.Tach}
	if err = cooling.Validate(s); err != nil {
		return err
	}
	if w.Mode != "none" {
		if control != nil {
			if err = control.Reconfigure(gpio.AsOutput(1)); err != nil {
				return err
			}
		} else {
			chip, e := rp1Chip()
			if e != nil {
				return e
			}
			defer chip.Close()
			line, e := chip.RequestLine(w.Control, gpio.AsOutput(1))
			if e != nil {
				return e
			}
			defer line.Close()
		}
	}

	if w.Mode == "internal-pwm" {
		chip, e := pwmChip(false)
		if e != nil {
			return e
		}
		channel := strconv.Itoa(pwmPins[w.Control].channel)
		path := filepath.Join(chip, "pwm"+channel)
		if _, e = os.Stat(path); e == nil {
			if e = writeValue(filepath.Join(path, "enable"), "0"); e != nil {
				return e
			}
			if e = writeValue(filepath.Join(chip, "unexport"), channel); e != nil {
				return e
			}
		}
	}
	return os.Remove(markerPath)
}
func writeValue(path, value string) error { return os.WriteFile(path, []byte(value), 0644) }

type hardware struct {
	wiring        Wiring
	control, tach *gpio.Line
	pwm           string
	pulses        atomic.Uint64
	rpm           *int
	since         time.Time
	actual        float64
}

func openHardware(w Wiring) (h *hardware, err error) {
	h = &hardware{wiring: w, since: time.Now(), actual: -1}
	if w.Mode == "none" {
		return h, nil
	}
	if !strings.Contains(readText("/proc/device-tree/model"), "Raspberry Pi 5") {
		return nil, fmt.Errorf("GPIO cooling currently supports Raspberry Pi 5 only")
	}
	chip, err := rp1Chip()
	if err != nil {
		return nil, err
	}
	defer chip.Close()
	pins := []int{w.Control}
	if w.Tach != nil {
		pins = append(pins, *w.Tach)
	}
	for _, pin := range pins {
		info, e := chip.LineInfo(pin)
		if e != nil {
			return nil, e
		}
		if info.Used {
			return nil, fmt.Errorf("GPIO%d is used by %s", pin, info.Consumer)
		}
		if e = checkPinFunction(pin); e != nil {
			return nil, e
		}
	}
	var pwmRoot string
	if w.Mode == "internal-pwm" {
		pwmRoot, err = pwmChip(true)
		if err != nil {
			return nil, err
		}
		h.pwm = filepath.Join(pwmRoot, fmt.Sprintf("pwm%d", pwmPins[w.Control].channel))
		if _, e := os.Stat(h.pwm); e == nil {
			return nil, fmt.Errorf("PWM channel is already in use")
		}
	}
	h.control, err = chip.RequestLine(w.Control, gpio.AsOutput(1))
	if err != nil {
		return nil, err
	}
	owned := h
	defer func() {
		if err != nil {
			_ = owned.close()
		}
	}()
	if w.Tach != nil {
		// RP1 single-edge interrupts can include opposite edges; count only falling events.
		h.tach, err = chip.RequestLine(*w.Tach, gpio.AsInput, gpio.WithPullUp, gpio.WithBothEdges, gpio.WithEventHandler(func(e gpio.LineEvent) {
			if e.Type == gpio.LineEventFallingEdge {
				owned.pulses.Add(1)
			}
		}))
		if err != nil {
			return nil, err
		}
	}
	if err = atomicJSON(markerPath, w); err != nil {
		return nil, err
	}
	if w.Mode == "internal-pwm" {
		if err = writeValue(filepath.Join(pwmRoot, "export"), strconv.Itoa(pwmPins[w.Control].channel)); err != nil {
			return nil, err
		}
		for _, v := range [][2]string{{"period", "40000"}, {"duty_cycle", "40000"}, {"enable", "1"}} {
			if err = writeValue(filepath.Join(h.pwm, v[0]), v[1]); err != nil {
				return nil, err
			}
		}
		if err = selectPWM(w.Control); err != nil {
			return nil, err
		}
	}
	return h, nil
}
func wait(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
func (h *hardware) tick(ctx context.Context, actual float64) error {
	if h.wiring.Mode == "internal-pwm" {
		if actual != h.actual {
			if err := writeValue(filepath.Join(h.pwm, "duty_cycle"), strconv.Itoa(int(math.Round(actual*40000)))); err != nil {
				return err
			}
		}
		wait(ctx, 25*time.Millisecond)
	} else if h.wiring.Mode == "external-pwm" {
		v := 0
		if actual > 0 {
			v = 1
		}
		if err := h.control.SetValue(v); err != nil {
			return err
		}
		if actual == 0 || actual == 1 {
			wait(ctx, 25*time.Millisecond)
		} else {
			wait(ctx, time.Duration(actual*float64(25*time.Millisecond)))
			if err := h.control.SetValue(0); err != nil {
				return err
			}
			wait(ctx, time.Duration((1-actual)*float64(25*time.Millisecond)))
		}
	} else {
		wait(ctx, 25*time.Millisecond)
	}
	h.actual = actual
	if h.tach != nil && time.Since(h.since) >= 2*time.Second {
		rpm := int(math.Round(float64(h.pulses.Swap(0)) * 30 / time.Since(h.since).Seconds()))
		h.rpm = &rpm
		h.since = time.Now()
	}
	return nil
}
func (h *hardware) close() error {
	if h.control == nil {
		return nil
	}
	err := failsafe(h.control)
	if h.tach != nil {
		err = errors.Join(err, h.tach.Close())
		h.tach = nil
	}
	err = errors.Join(err, h.control.Close())
	h.control = nil
	return err
}
