package oled

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/powercontrol"
)

type Device struct {
	file     *os.File
	settings Settings
}

func checkCooling(s Settings) error {
	if e := powercontrol.CheckPins(s.SDA, s.SCL); e != nil {
		return e
	}
	var cooling struct {
		HardwareMode string `json:"hardwareMode"`
		ControlGPIO  int    `json:"controlGPIO"`
		TachGPIO     *int   `json:"tachGPIO"`
	}
	raw, e := os.ReadFile("/etc/panasms-cooling/config.json")
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = json.Unmarshal(raw, &cooling); e != nil {
		return fmt.Errorf("Cannot check cooling GPIO ownership: %w", e)
	}
	if cooling.HardwareMode == "" {
		cooling.HardwareMode = "external-pwm"
		cooling.ControlGPIO = 27
	}
	if cooling.HardwareMode != "none" && (cooling.ControlGPIO == s.SDA || cooling.ControlGPIO == s.SCL || cooling.TachGPIO != nil && (*cooling.TachGPIO == s.SDA || *cooling.TachGPIO == s.SCL)) {
		return fmt.Errorf("Selected GPIO pins are assigned to cooling")
	}
	return nil
}
func prepare(ctx context.Context, s Settings) error {
	if !Supported() {
		return fmt.Errorf("I2C display is not supported on this system")
	}
	if e := checkCooling(s); e != nil {
		return e
	}
	matched := true
	for i, pin := range []int{s.SDA, s.SCL} {
		output, e := commandOutput(ctx, "pinctrl", "get", strconv.Itoa(pin))
		if e != nil {
			return e
		}
		function := []string{"SDA", "SCL"}[i] + strconv.Itoa(s.Bus)
		if strings.Contains(output, fmt.Sprintf("GPIO%d = %s", pin, function)) {
			continue
		}
		matched = false
		if !strings.Contains(output, fmt.Sprintf("GPIO%d = none", pin)) && !strings.Contains(output, fmt.Sprintf("GPIO%d = input", pin)) {
			return fmt.Errorf("GPIO%d is already assigned: %s", pin, strings.TrimSpace(output))
		}
	}
	if !matched {
		if _, e := os.Stat(fmt.Sprintf("/sys/class/i2c-adapter/i2c-%d", s.Bus)); e == nil {
			return fmt.Errorf("I2C bus is already using other pins. Restart the NAS to apply the saved pins; if this persists, check I2C boot configuration")
		} else if !os.IsNotExist(e) {
			return e
		}
		// Never remove a live overlay: RP1 drivers may still hold references to it.
		if e := run(ctx, "dtoverlay", fmt.Sprintf("i2c%d-pi5", s.Bus), fmt.Sprintf("pins_%d_%d", s.SDA, s.SCL)); e != nil {
			return e
		}
	}
	if _, e := os.Stat(fmt.Sprintf("/dev/i2c-%d", s.Bus)); os.IsNotExist(e) {
		return run(ctx, "modprobe", "i2c-dev")
	}
	return nil
}
func Open(s Settings) (*Device, error) {
	f, e := os.OpenFile("/dev/i2c-"+strconv.Itoa(s.Bus), os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	if e = unix.IoctlSetInt(int(f.Fd()), 0x0703, s.Address); e != nil {
		f.Close()
		return nil, e
	}
	d := &Device{f, s}
	init := []byte{0xae, 0xd5, 0x80, 0xa8, 0x3f, 0xd3, 0x00, 0x40}
	if s.Controller == "sh1106" {
		init = append(init, 0xad, 0x8b)
	} else {
		init = append(init, 0x8d, 0x14, 0x20, 0x02)
	}
	init = append(init, 0xa1, 0xc8, 0xda, 0x12, 0x81, byte(s.Brightness*255/100), 0xd9, 0x22, 0xdb, 0x20, 0xa4, 0xa6)
	if e = d.command(init...); e != nil {
		f.Close()
		return nil, e
	}
	return d, nil
}
func (d *Device) write(kind byte, values []byte) error {
	data := append([]byte{kind}, values...)
	n, e := d.file.Write(data)
	if e == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return e
}
func (d *Device) command(values ...byte) error { return d.write(0, values) }
func pageCommand(controller string, page int) []byte {
	offset := byte(0)
	if controller == "sh1106" {
		offset = 2
	}
	return []byte{byte(0xb0 + page), offset, 0x10}
}
func (d *Device) Display(frame [1024]byte) error {
	for page := 0; page < 8; page++ {
		if e := d.command(pageCommand(d.settings.Controller, page)...); e != nil {
			return e
		}
		for x := 0; x < 128; x += 32 {
			if e := d.write(0x40, frame[page*128+x:page*128+x+32]); e != nil {
				return e
			}
		}
	}
	return d.command(0xaf)
}
func (d *Device) Close() error {
	e := d.command(0xae)
	ce := d.file.Close()
	if e != nil {
		return e
	}
	return ce
}
