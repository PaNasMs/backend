package modules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDisabledAndMissingModulesFailClosed(t *testing.T) {
	old := Root
	Root = t.TempDir()
	t.Cleanup(func() { Root = old })
	if Enabled("files") {
		t.Fatal("missing module enabled")
	}
	os.WriteFile(filepath.Join(Root, "registry.json"), []byte(`{"files":{"id":"files","enabled":false}}`), 0600)
	if _, e := Client("files"); e == nil {
		t.Fatal("disabled module accessible")
	}
	os.WriteFile(filepath.Join(Root, "registry.json"), []byte(`{"files":{"id":"files","enabled":true}}`), 0600)
	if !Enabled("files") {
		t.Fatal("enabled module unavailable")
	}
	if Enabled("../files") {
		t.Fatal("invalid ID accepted")
	}
}
