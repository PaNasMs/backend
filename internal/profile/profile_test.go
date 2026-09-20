package profile

import "testing"

func TestNames(t *testing.T) {
	for _, name := range []string{"Павел", "Pasha", ""} {
		if !ValidName(name) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"a:b", "a\nb", "a,b", "a\x00b"} {
		if ValidName(name) {
			t.Fatal("accepted control syntax")
		}
	}
}
