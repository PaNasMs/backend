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

func TestPendingTransactionBlocksProxyAndNativeDispatch(t *testing.T) {
	old := Root
	Root = t.TempDir()
	t.Cleanup(func() { Root = old })
	if err := os.WriteFile(filepath.Join(Root, "registry.json"), []byte(`{"files":{"id":"files","enabled":true}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if !Enabled("files") {
		t.Fatal("valid baseline unavailable")
	}
	if err := os.Mkdir(filepath.Join(Root, ".transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	if Enabled("files") || len(Read()) != 0 {
		t.Fatal("pending registry exposed to proxy")
	}
	if _, err := Client("files"); err == nil {
		t.Fatal("pending module client admitted")
	}
	if _, err := Operation("queries", "files", func(string, string) bool { return false }); err == nil {
		t.Fatal("pending native operation admitted")
	}
}
