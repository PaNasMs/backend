package systemops

import "testing"

func TestName(t *testing.T) {
	valid := []string{"a", "_x", "bob", "user_1", "svc-name", "abcdefghijklmnopqrstuvwxyz01234"}
	for _, v := range valid {
		if _, err := Name(v); err != nil {
			t.Errorf("Name(%q) rejected: %v", v, err)
		}
	}
	invalid := []string{"", "1abc", "-x", "Bob", "a b", "ünïcode", "abcdefghijklmnopqrstuvwxyz012345", "a.b"}
	for _, v := range invalid {
		if _, err := Name(v); err == nil {
			t.Errorf("Name(%q) accepted, want rejection", v)
		}
	}
}

func TestInteger(t *testing.T) {
	if _, err := Integer(5, 0, 10); err != nil {
		t.Errorf("in range rejected: %v", err)
	}
	if _, err := Integer(0, 0, 10); err != nil {
		t.Errorf("low bound rejected: %v", err)
	}
	if _, err := Integer(10, 0, 10); err != nil {
		t.Errorf("high bound rejected: %v", err)
	}
	for _, v := range []int64{-1, 11} {
		if _, err := Integer(v, 0, 10); err == nil {
			t.Errorf("Integer(%d) accepted, want rejection", v)
		}
	}
}

func TestCleanPath(t *testing.T) {
	valid := []string{"/", "/etc/panasms/web.env", "/var/lib/panasms-agent"}
	for _, v := range valid {
		if _, err := CleanPath(v); err != nil {
			t.Errorf("CleanPath(%q) rejected: %v", v, err)
		}
	}
	invalid := []string{
		"relative/path",
		"/a/../b",
		"/a//b",
		"/a/./b",
		"/trailing/",
		"/has\x00null",
		"/has\ttab",
	}
	for _, v := range invalid {
		if _, err := CleanPath(v); err == nil {
			t.Errorf("CleanPath(%q) accepted, want rejection", v)
		}
	}
}
