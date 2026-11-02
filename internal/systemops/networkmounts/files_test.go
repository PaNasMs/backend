package networkmounts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialLifecycleAndReplacementPreservation(t *testing.T) {
	s, p := fixture(t)
	state := &transaction{Schema: 1, Point: param(p, "point"), Source: param(p, "target"), FSType: "cifs", Phase: "preparing"}
	if err := s.save(state); err != nil {
		t.Fatal(err)
	}
	if err := s.createCredential(state, p); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.credentials, Key(state.Point))
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), "secret-value") {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	journal, _ := os.ReadFile(filepath.Join(s.root, Key(state.Point)+".json"))
	if strings.Contains(string(journal), "secret-value") {
		t.Fatal("secret in recovery journal")
	}
	if err = s.removeCredential(state); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err = s.createCredential(state, p); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+"-original"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, []byte("foreign preserved"), 0600)
	if err = s.removeCredential(state); err == nil {
		t.Fatal("foreign inode deleted")
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != "foreign preserved" {
		t.Fatal(string(raw))
	}
}
func TestCreateTargetRejectsSymlinkWithoutEscaping(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "link")
	os.Symlink(outside, link)
	if _, file, err := closestDirectory(filepath.Join(link, "child")); err == nil {
		file.Close()
		t.Fatal("followed link")
	}
	if _, err := os.Stat(filepath.Join(outside, "child")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	path := filepath.Join(root, "real", "child")
	witness, ancestor, err := closestDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	ancestor.Close()
	file, err := createPinnedTarget(path, witness)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err = sameDirectory(file, path); err != nil {
		t.Fatal(err)
	}
	os.Rename(path, path+"-old")
	os.Mkdir(path, 0700)
	if err = sameDirectory(file, path); err == nil {
		t.Fatal("replacement accepted")
	}
}
