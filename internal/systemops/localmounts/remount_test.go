package localmounts

import (
	"panasms.local/backend/internal/systemops/folders"
	"testing"
)

func TestMissingSourceDoesNotAuthorizeForeignUnmount(t *testing.T) {
	for _, m := range []folders.LiveMount{
		{FSType: "tmpfs", Root: "/", Device: "0:4294967000", Source: "/dev/panasms-absent-fixture"},
		{FSType: "fuse.sshfs", Root: "/", Device: "0:4294967000", Source: "/dev/panasms-absent-fixture"},
		{FSType: "ext4", Root: "/selected-directory", Device: "4094:999999", Source: "/dev/panasms-absent-fixture"},
	} {
		if staleBlockMount(m) {
			t.Errorf("foreign %s mount considered safe to disconnect", m.FSType)
		}
	}
	physical := folders.LiveMount{FSType: "ext4", Root: "/", Device: "4094:999999", Source: "/dev/panasms-absent-fixture"}
	if !staleBlockMount(physical) {
		t.Fatal("missing block-backed volume was not recognized")
	}
}
