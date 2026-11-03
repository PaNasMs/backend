package modulelifecycle

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type archiveEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func archiveFixture(t *testing.T, change func(Manifest, *[]archiveEntry), alterManifest bool) ([]byte, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := fixtureManifest(t)
	m["signer"] = "fixture"
	payload := []byte("export default 'signed module';")
	hash := sha256.Sum256(payload)
	m["files"] = map[string]any{"ui/index.js": hex.EncodeToString(hash[:])}
	entries := []archiveEntry{{"bundle.json", []byte(`{"root":"example"}`), 0644}, {"modules/example/ui/index.js", payload, 0644}}
	if change != nil {
		change(m, &entries)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, raw)
	if alterManifest {
		raw = bytes.Replace(raw, []byte(`"Example"`), []byte(`"Changed"`), 1)
	}
	prefix := "modules/" + text(m, "id") + "/"
	entries = append(entries, archiveEntry{prefix + "manifest.json", raw, 0644}, archiveEntry{prefix + "signature", signature, 0644})
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(entry.mode)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes(), public
}

func inspectFixture(raw []byte, public ed25519.PublicKey) (*bundle, error) {
	return inspectBundle(bytes.NewReader(raw), int64(len(raw)), "0.2.34", "amd64", func(signer string) (ed25519.PublicKey, error) {
		if signer != "fixture" {
			return nil, reject("Unknown publisher: " + signer)
		}
		return public, nil
	})
}

func TestSignedArchiveIntegrityAndPayloadWhitelist(t *testing.T) {
	raw, public := archiveFixture(t, nil, false)
	bundle, err := inspectFixture(raw, public)
	if err != nil || bundle.root != "example" || len(bundle.manifests) != 1 {
		t.Fatal(bundle, err)
	}
	for _, name := range []string{"manifest", "payload", "unknown", "duplicate", "symlink", "parent", "missing-root", "namespace", "unknown-publisher"} {
		t.Run(name, func(t *testing.T) {
			change := func(m Manifest, entries *[]archiveEntry) {
				switch name {
				case "payload":
					(*entries)[1].data = []byte("corrupted payload")
				case "unknown":
					*entries = append(*entries, archiveEntry{"modules/example/not-declared", []byte("extra"), 0644})
				case "duplicate":
					*entries = append(*entries, (*entries)[0])
				case "symlink":
					(*entries)[1].mode = os.ModeSymlink | 0777
				case "parent":
					*entries = append(*entries, archiveEntry{"modules/example/../outside", []byte("outside"), 0644})
				case "missing-root":
					(*entries)[0].data = []byte(`{"root":"absent"}`)
				case "namespace":
					m["actions"] = []any{"user.delete"}
				case "unknown-publisher":
					m["signer"] = "unknown"
				}
			}
			raw, public := archiveFixture(t, change, name == "manifest")
			if _, err := inspectFixture(raw, public); err == nil {
				t.Fatal("unsafe or corrupted archive accepted")
			}
		})
	}
}

func TestArchiveRejectsDeclaredExpansionBeforeReadingPayload(t *testing.T) {
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	header := &zip.FileHeader{Name: "oversized", Method: zip.Store, CompressedSize64: 1, UncompressedSize64: maxExpandedArchive + 1}
	file, err := writer.CreateRaw(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = inspectFixture(buffer.Bytes(), nil); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatal(err)
	}
}

func TestPublicKeyTrustRejectsReplacementLinksAndWritableKeys(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for _, variant := range []string{"valid", "symlink", "hardlink", "writable", "trailing-key", "parent-link"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "fixture.pem")
			if err := os.WriteFile(path, raw, 0644); err != nil {
				t.Fatal(err)
			}
			switch variant {
			case "symlink":
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".saved", path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".linked"); err != nil {
					t.Fatal(err)
				}
			case "writable":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "trailing-key":
				if err := os.WriteFile(path, append(raw, raw...), 0644); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				root = link
			}
			got, err := readPublicKey(root, "fixture", uint32(os.Geteuid()))
			if variant == "valid" {
				if err != nil || !bytes.Equal(got, public) {
					t.Fatal(got, err)
				}
			} else if err == nil {
				t.Fatal("unsafe signing key accepted")
			}
		})
	}
}

func TestRegistryIdentityAndExactFutureMetadata(t *testing.T) {
	for _, raw := range []string{`null`, `{"example":{"id":"other"}}`, `{"../escape":{"id":"../escape"}}`, `{} {}`} {
		if _, err := decodeRegistry([]byte(raw)); err == nil {
			t.Fatal("invalid registry accepted", raw)
		}
	}
	registry, err := decodeRegistry([]byte(`{"example":{"id":"example","future":{"counter":9007199254740993}}}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(registry)
	if !bytes.Contains(raw, []byte("9007199254740993")) {
		t.Fatal("registry number changed", string(raw))
	}
}
