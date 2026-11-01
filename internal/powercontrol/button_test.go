package powercontrol

import (
	"strings"
	"testing"
	"time"
)

func TestButtonStartupHoldBounceAndSingleShutdown(t *testing.T) {
	var g buttonGesture
	now := time.Unix(0, 0)
	sample := func(v int, milliseconds int, want bool) {
		t.Helper()
		now = now.Add(time.Duration(milliseconds) * time.Millisecond)
		if got := g.sample(v, now); got != want {
			t.Fatalf("value %d: got %v want %v", v, got, want)
		}
	}
	sample(0, 0, false)
	sample(0, 10000, false)
	sample(1, 0, false)
	sample(1, 100, false)
	if !g.armed {
		t.Fatal("not armed after startup release")
	}
	sample(0, 20, false)
	sample(1, 20, false)
	sample(1, 150, false)
	sample(0, 0, false)
	sample(0, 100, false)
	sample(1, 0, false)
	sample(0, 20, false)
	sample(0, 100, false)
	sample(1, 0, false)
	sample(1, 100, true)
	sample(0, 100, false)
	sample(0, 100, false)
	sample(1, 100, false)
	sample(1, 100, false)
}
func TestFreshButtonWaitsForStableRelease(t *testing.T) {
	var g buttonGesture
	now := time.Now()
	g.sample(1, now)
	g.sample(0, now.Add(25*time.Millisecond))
	if g.sample(0, now.Add(time.Second)) || g.armed {
		t.Fatal("startup bounce armed button")
	}
}
func TestLegacyPowerSettingsDoNotEnableButton(t *testing.T) {
	raw := []byte(begin + "\n[all]\n# GPIO=25\ndtoverlay=gpio-poweroff,gpiopin=25\n" + end)
	b, e := parseButton(raw)
	if e != nil || b.Enabled || b.GPIO != 22 {
		t.Fatalf("%+v %v", b, e)
	}
	next, e := renderUpdate(raw, Update{Settings: Settings{true, 25}, Expected: Settings{true, 25}})
	if e != nil {
		t.Fatal(e)
	}
	b, e = parseButton(next)
	if e != nil || b.Enabled {
		t.Fatalf("upgrade activated button: %+v %v", b, e)
	}
}
func TestButtonSavePreservationAndConcurrentConflict(t *testing.T) {
	off, on := ButtonSettings{false, 22}, ButtonSettings{true, 22}
	raw, _ := render(nil, Settings{true, 25})
	next, e := renderUpdate(raw, Update{Settings: Settings{true, 25}, Expected: Settings{true, 25}, Button: &on, ExpectedButton: &off})
	if e != nil {
		t.Fatal(e)
	}
	b, e := parseButton(next)
	if e != nil || b != on {
		t.Fatalf("%+v %v", b, e)
	}
	next, e = renderUpdate(next, Update{Settings: Settings{true, 26}, Expected: Settings{true, 25}})
	if e != nil {
		t.Fatal(e)
	}
	b, _ = parseButton(next)
	if b != on {
		t.Fatal("legacy update lost button settings")
	}
	if _, e = renderUpdate(next, Update{Settings: Settings{true, 26}, Expected: Settings{true, 26}, Button: &off, ExpectedButton: &off}); e != ErrConflict {
		t.Fatalf("stale button update: %v", e)
	}
}
func TestInvalidButtonConfigAndInput(t *testing.T) {
	for _, raw := range []string{`{"enabled":true,"gpio":1}`, `{"enabled":true,"gpio":28}`, `{"enabled":true,"gpio":22,"unknown":0}`, `{"enabled":true,"gpio":22} {}`} {
		if _, e := parseButton([]byte(begin + "\n# PaNasMs shutdown button=" + raw + "\n" + end)); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, e := Decode(strings.NewReader(`{"enabled":true,"gpio":25,"expected":{"enabled":true,"gpio":25},"button":{"enabled":true,"gpio":22}}`)); e == nil {
		t.Fatal("missing expected button accepted")
	}
	state := State{Button: ButtonSettings{true, 22}}
	if state.checkPins(22) == nil {
		t.Fatal("button not reserved for OLED/cooling")
	}
}
