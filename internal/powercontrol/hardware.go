package powercontrol

import (
	"context"
	"fmt"
	gpio "github.com/warthog618/go-gpiocdev"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func checkAvailable(pin int) error {
	found := false
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
		if info.Used {
			return fmt.Errorf("GPIO%d is already in use by %s", pin, info.Consumer)
		}
		found = true
		break
	}
	if !found {
		return fmt.Errorf("RP1 GPIO controller is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, e := exec.CommandContext(ctx, "pinctrl", "get", strconv.Itoa(pin)).CombinedOutput()
	if e != nil {
		return fmt.Errorf("Cannot inspect GPIO%d: %w", pin, e)
	}
	text := string(out)
	if !strings.Contains(text, fmt.Sprintf("GPIO%d = none", pin)) && !strings.Contains(text, fmt.Sprintf("GPIO%d = input", pin)) {
		return fmt.Errorf("GPIO%d is assigned to a peripheral", pin)
	}
	return nil
}
