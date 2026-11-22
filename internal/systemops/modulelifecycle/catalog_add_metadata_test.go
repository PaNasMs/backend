package modulelifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRecoveryPreservesMetadataOnlyEditsToDisplacedConfig(t *testing.T) {
	for _, edit := range []string{"timestamps", "xattr"} {
		t.Run(edit, func(t *testing.T) {
			c, _ := catalogFixture(t)
			p := servePendingRepository(t, &c)
			original, err := os.OpenFile(c.config, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer original.Close()
			c.sourceBoundary = stopAfterConfigReplace
			result, err := executePlannedSource(t, c, "module.source-add", p)
			if err != nil || !bytes.Contains(result, []byte(`"warnings"`)) {
				t.Fatalf("expected interrupted cleanup: %s %v", result, err)
			}
			raw, err := os.ReadFile(filepath.Join(c.root, sourceIntent))
			if err != nil {
				t.Fatal(err)
			}
			var change sourceChange
			if err := json.Unmarshal(raw, &change); err != nil {
				t.Fatal(err)
			}
			fd := int(original.Fd())
			const attribute = "user.operator-note"
			if edit == "xattr" {
				err := unix.Fsetxattr(fd, attribute, []byte("preserve"), 0)
				if errors.Is(err, unix.ENOTSUP) {
					t.Skip("test filesystem does not support user xattrs")
				}
				if err != nil {
					t.Fatal(err)
				}
			} else if err := unix.Futimes(fd, []unix.Timeval{{Sec: 1000000000}, {Sec: 1100000000}}); err != nil {
				t.Fatal(err)
			}
			var before unix.Stat_t
			if err := unix.Fstat(fd, &before); err != nil {
				t.Fatal(err)
			}
			restarted := catalogService{lifecycle: c.lifecycle, config: c.config, download: c.download}
			if _, err := restarted.recoverCatalog(t.Context(), "module.source-add"); err != nil {
				t.Fatal(err)
			}
			slot := filepath.Join(filepath.Dir(c.config), sourceAddStageRoot, change.AddID)
			var after unix.Stat_t
			if err := unix.Lstat(slot, &after); err != nil {
				t.Fatal(err)
			}
			if after.Ino != before.Ino || after.Mtim != before.Mtim || after.Atim != before.Atim {
				t.Fatal("recovery removed or changed the operator's timestamps")
			}
			if edit == "xattr" {
				var value [32]byte
				n, err := unix.Getxattr(slot, attribute, value[:])
				if err != nil || string(value[:max(0, n)]) != "preserve" {
					t.Fatalf("changed operator xattr: %v", err)
				}
			}
			key, err := restarted.activePublisherKey("pending")
			if err != nil || publicFingerprint(key) != p["keyFingerprint"] {
				t.Fatalf("missing confirmed publisher: %v", err)
			}
		})
	}
}
