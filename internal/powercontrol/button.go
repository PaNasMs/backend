package powercontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	gpio "github.com/warthog618/go-gpiocdev"
)

type ButtonSettings struct {
	Enabled bool `json:"enabled"`
	GPIO    int  `json:"gpio"`
}

func (b *ButtonSettings) UnmarshalJSON(raw []byte) error {
	var value struct {
		Enabled *bool `json:"enabled"`
		GPIO    *int  `json:"gpio"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil || d.Decode(new(any)) != io.EOF || value.Enabled == nil || value.GPIO == nil {
		return errors.New("Shutdown button settings require explicit enabled and gpio fields")
	}
	*b = ButtonSettings{Enabled: *value.Enabled, GPIO: *value.GPIO}
	return b.Validate()
}

func (b ButtonSettings) Validate() error {
	if b.GPIO < 2 || b.GPIO > 27 {
		return errors.New("Shutdown button GPIO must be between 2 and 27")
	}
	return nil
}
func parseButton(raw []byte) (ButtonSettings, error) {
	b := ButtonSettings{GPIO: 22}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		value, ok := strings.CutPrefix(strings.TrimSpace(line), "# PaNasMs shutdown button=")
		if !ok {
			continue
		}
		if found {
			return b, errors.New("Duplicate shutdown button settings")
		}
		found = true
		d := json.NewDecoder(strings.NewReader(value))
		d.DisallowUnknownFields()
		if e := d.Decode(&b); e != nil {
			return b, e
		}
		if d.Decode(new(any)) != io.EOF {
			return b, errors.New("Invalid shutdown button settings")
		}
	}
	return b, b.Validate()
}
func renderButton(raw []byte, b ButtonSettings) ([]byte, error) {
	if e := b.Validate(); e != nil {
		return nil, e
	}
	lines := strings.Split(string(raw), "\n")
	encoded, _ := json.Marshal(b)
	marker := "# PaNasMs shutdown button=" + string(encoded)
	found := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "# PaNasMs shutdown button=") {
			lines[i] = marker
			found = true
		}
	}
	if !found {
		return []byte(strings.TrimRight(string(raw), "\n") + "\n" + marker + "\n"), nil
	}
	return []byte(strings.Join(lines, "\n")), nil
}

var buttonRuntime = struct {
	sync.RWMutex
	state string
}{state: "disabled"}

func buttonStatus() string {
	buttonRuntime.RLock()
	defer buttonRuntime.RUnlock()
	return buttonRuntime.state
}
func setButtonStatus(s string) {
	buttonRuntime.Lock()
	defer buttonRuntime.Unlock()
	buttonRuntime.state = s
}

// Require a stable release after startup, then a full debounced press/release.
type buttonGesture struct {
	value                              int
	since                              time.Time
	initialized, armed, pressed, fired bool
}

func (g *buttonGesture) sample(value int, now time.Time) bool {
	if !g.initialized || value != g.value {
		g.initialized = true
		g.value = value
		g.since = now
		return false
	}
	if now.Sub(g.since) < 100*time.Millisecond || g.fired {
		return false
	}
	if !g.armed {
		if value == 1 {
			g.armed = true
		}
		return false
	}
	if value == 0 {
		g.pressed = true
		return false
	}
	if g.pressed {
		g.fired = true
		return true
	}
	return false
}

const buttonConsumer = "panasms-shutdown-button"

func checkButtonAvailable(pin int) error {
	for _, name := range gpio.Chips() {
		c, e := gpio.NewChip(name)
		if e != nil {
			return e
		}
		if c.Label != "pinctrl-rp1" {
			c.Close()
			continue
		}
		info, e := c.LineInfo(pin)
		c.Close()
		if e != nil {
			return e
		}
		if info.Used && info.Consumer == buttonConsumer {
			return nil
		}
	}
	return checkAvailable(pin)
}
func openButton(pin int) (*gpio.Line, error) {
	if e := checkAvailable(pin); e != nil {
		return nil, e
	}
	for _, name := range gpio.Chips() {
		c, e := gpio.NewChip(name)
		if e != nil {
			return nil, e
		}
		if c.Label != "pinctrl-rp1" {
			c.Close()
			continue
		}
		line, e := c.RequestLine(pin, gpio.AsInput, gpio.WithPullUp, gpio.WithConsumer(buttonConsumer))
		c.Close()
		return line, e
	}
	return nil, errors.New("RP1 GPIO controller is unavailable")
}

func RunButton(ctx context.Context) {
	var line *gpio.Line
	var settings ButtonSettings
	var gesture buttonGesture
	closeLine := func() {
		if line != nil {
			line.Close()
			line = nil
		}
		gesture = buttonGesture{}
	}
	defer closeLine()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var nextCheck time.Time
	var lastError string
	reportError := func(e error) {
		setButtonStatus("error")
		if text := e.Error(); text != lastError {
			log.Printf("shutdown button: %s", text)
			lastError = text
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if !now.Before(nextCheck) {
				nextCheck = now.Add(time.Second)
				unlock, e := Lock()
				if e != nil {
					if !errors.Is(e, ErrGPIOBusy) {
						closeLine()
						reportError(e)
					}
					continue
				}
				state, e := Read()
				if e != nil || !state.Supported || !state.Button.Enabled {
					closeLine()
					setButtonStatus("disabled")
					if e != nil {
						reportError(e)
					} else {
						lastError = ""
					}
				} else if !state.Config.Enabled || state.RebootRequired || state.Button.GPIO == state.Config.GPIO {
					closeLine()
					setButtonStatus("waitingForPowerControl")
					lastError = ""
				} else {
					if settings != state.Button {
						closeLine()
					}
					settings = state.Button
					if line == nil {
						e = checkConfigured("/", settings.GPIO)
						if e == nil {
							line, e = openButton(settings.GPIO)
						}
						if e != nil {
							reportError(e)
						} else {
							setButtonStatus("waitingForRelease")
						}
					}
				}
				unlock()
			}
			if line == nil {
				continue
			}
			value, e := line.Value()
			if e != nil {
				closeLine()
				reportError(fmt.Errorf("read input: %w", e))
				continue
			}
			if !gesture.fired {
				lastError = ""
			}
			if gesture.sample(value, now) {
				unlock, err := Lock()
				if err != nil {
					gesture = buttonGesture{}
					if !errors.Is(err, ErrGPIOBusy) {
						closeLine()
						reportError(err)
					}
					continue
				}
				latest, err := Read()
				if err != nil || latest.Button != settings || !latest.Button.Enabled || !latest.Config.Enabled || latest.RebootRequired {
					unlock()
					closeLine()
					continue
				}
				setButtonStatus("shutdownRequested")
				commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				out, e := exec.CommandContext(commandCtx, "/usr/bin/systemctl", "--no-block", "poweroff").CombinedOutput()
				cancel()
				unlock()
				if e != nil {
					gesture = buttonGesture{}
					reportError(fmt.Errorf("request shutdown: %w: %s", e, strings.TrimSpace(string(out))))
				}
			} else if gesture.armed && !gesture.fired {
				setButtonStatus("armed")
			}
		}
	}
}
