package cooling

import "testing"

func TestValidate(t *testing.T) {
	for _, s := range []Settings{{CPUProfile: "balanced", Profile: "quiet", SampleSeconds: 60}, {CPUProfile: "balanced", Profile: "balanced", SampleSeconds: 30}, {CPUProfile: "balanced", Profile: "performance", SampleSeconds: 600}} {
		if Validate(s) != nil {
			t.Fatal(s)
		}
	}
	for _, s := range []Settings{{CPUProfile: "balanced", Profile: "off", SampleSeconds: 60}, {CPUProfile: "balanced", Profile: "balanced", SampleSeconds: 0}, {CPUProfile: "balanced", Profile: "quiet", SampleSeconds: 601}} {
		if Validate(s) == nil {
			t.Fatal(s)
		}
	}
}

func TestHardwareSettings(t *testing.T) {
	tach := 24
	base := Settings{CPUProfile: "quiet", Profile: "quiet", SampleSeconds: 60, HardwareMode: "internal-pwm", ControlGPIO: 18, TachGPIO: &tach}
	if err := Validate(base); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []int{0, 27, 28} {
		s := base
		s.ControlGPIO = pin
		if Validate(s) == nil {
			t.Fatalf("accepted unsupported hardware PWM pin %d", pin)
		}
	}
	base.TachGPIO = &base.ControlGPIO
	if Validate(base) == nil {
		t.Fatal("accepted shared tach/control pin")
	}
	base.HardwareMode = "none"
	if Validate(base) != nil {
		t.Fatal("disabled hardware should not claim pins")
	}
	legacy := normalize(Settings{})
	if legacy.HardwareMode != "external-pwm" || legacy.ControlGPIO != 27 {
		t.Fatal("legacy configuration changed wiring")
	}
}
