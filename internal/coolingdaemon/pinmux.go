package coolingdaemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	gpio "github.com/warthog618/go-gpiocdev"
)

func rp1Chip() (*gpio.Chip, error) {
	for _, p := range gpio.Chips() {
		c, err := gpio.NewChip(p, gpio.WithConsumer("panasms-cooling"), gpio.WithABIVersion(2))
		if err == nil {
			if c.Label == "pinctrl-rp1" {
				return c, nil
			}
			c.Close()
		}
	}
	return nil, fmt.Errorf("RP1 GPIO controller is unavailable")
}
func pinmuxRoot() string {
	paths, _ := filepath.Glob("/sys/kernel/debug/pinctrl/*pinctrl-rp1")
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(p, "pinmux-select")); err == nil {
			return p
		}
	}
	return ""
}
func freePinFunction(raw string, pin int) error {
	prefix := fmt.Sprintf("pin %d (gpio%d) ", pin, pin)
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, prefix) {
			_, function, ok := strings.Cut(line, " function ")
			if !ok {
				break
			}
			fields := strings.Fields(function)
			if len(fields) > 0 && (fields[0] == "gpio" || fields[0] == "none") {
				return nil
			}
			return fmt.Errorf("GPIO%d is assigned to a peripheral", pin)
		}
	}
	return fmt.Errorf("cannot identify GPIO%d pin function", pin)
}
func checkPinFunction(pin int) error {
	if root := pinmuxRoot(); root != "" {
		raw, err := os.ReadFile(filepath.Join(root, "pins"))
		if err != nil {
			return err
		}
		return freePinFunction(string(raw), pin)
	}
	state, err := pinctrl("get", strconv.Itoa(pin))
	if err != nil {
		return err
	}
	for i := 0; i < 9; i++ {
		if strings.Contains(string(state), fmt.Sprintf(" a%d ", i)) {
			return fmt.Errorf("GPIO%d is assigned to a peripheral", pin)
		}
	}
	return nil
}
func selectPWM(pin int) error {
	function := pwmPins[pin].function
	if root := pinmuxRoot(); root != "" {
		return writeValue(filepath.Join(root, "pinmux-select"), fmt.Sprintf("gpio%d alt%s", pin, strings.TrimPrefix(function, "a")))
	}
	_, err := pinctrl("set", strconv.Itoa(pin), function)
	return err
}
