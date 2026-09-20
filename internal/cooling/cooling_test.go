package cooling

import "testing"

func TestValidate(t *testing.T) {
	for _, s := range []Settings{{"balanced", "quiet", 60}, {"balanced", "balanced", 30}, {"balanced", "performance", 600}} {
		if Validate(s) != nil {
			t.Fatal(s)
		}
	}
	for _, s := range []Settings{{"balanced", "off", 60}, {"balanced", "balanced", 0}, {"balanced", "quiet", 601}} {
		if Validate(s) == nil {
			t.Fatal(s)
		}
	}
}
