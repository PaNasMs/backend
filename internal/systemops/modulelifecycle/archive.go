package modulelifecycle

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

const maxArchive = 128 << 20
const maxExpandedArchive = 256 << 20

var manifestPathPattern = regexp.MustCompile(`^modules/[a-z][a-z0-9-]{1,39}/manifest\.json$`)
var signerPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type bundle struct {
	root      string
	manifests Registry
	files     map[string]*zip.File
}

func archiveBytes(file *zip.File, limit int64) ([]byte, error) {
	if file == nil || file.UncompressedSize64 > uint64(limit) {
		return nil, reject("Archive too large")
	}
	reader, err := file.Open()
	if err != nil {
		return nil, reject("Invalid module archive")
	}
	defer reader.Close()
	raw, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || int64(len(raw)) > limit || uint64(len(raw)) != file.UncompressedSize64 {
		return nil, reject("Invalid module archive")
	}
	return raw, nil
}

func verifyArchiveFile(file *zip.File, expected string) error {
	reader, err := file.Open()
	if err != nil {
		return reject("Corrupted file: " + file.Name)
	}
	defer reader.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(reader, int64(file.UncompressedSize64)+1))
	if err != nil || uint64(size) != file.UncompressedSize64 || hex.EncodeToString(hash.Sum(nil)) != expected {
		return reject("Corrupted file: " + file.Name)
	}
	return nil
}

func inspectBundle(source io.ReaderAt, size int64, core, architecture string, key func(string) (ed25519.PublicKey, error)) (*bundle, error) {
	if size < 0 || size > maxArchive {
		return nil, reject("Archive too large")
	}
	archive, err := zip.NewReader(source, size)
	if err != nil {
		return nil, reject("Invalid module archive")
	}
	if len(archive.File) > 6000 {
		return nil, reject("Archive too large")
	}
	files := make(map[string]*zip.File, len(archive.File))
	var expanded uint64
	for _, file := range archive.File {
		if _, exists := files[file.Name]; exists {
			return nil, reject("Archive contains duplicate paths")
		}
		if !file.Mode().IsRegular() || file.Flags&1 != 0 {
			return nil, reject("Archive must contain only regular, unencrypted files")
		}
		if strings.HasPrefix(file.Name, "/") {
			return nil, reject("Unsafe archive path")
		}
		for _, component := range strings.Split(file.Name, "/") {
			if component == "" || component == "." || component == ".." {
				return nil, reject("Unsafe archive path")
			}
		}
		if file.UncompressedSize64 > maxExpandedArchive-expanded {
			return nil, reject("Archive too large")
		}
		expanded += file.UncompressedSize64
		files[file.Name] = file
	}
	rootFile := files["bundle.json"]
	if rootFile == nil || rootFile.UncompressedSize64 > 4096 {
		return nil, reject("Archive manifest is missing")
	}
	raw, err := archiveBytes(rootFile, 4096)
	if err != nil {
		return nil, err
	}
	var declaration struct {
		Root string `json:"root"`
	}
	if err = systemops.Decode(raw, &declaration); err != nil {
		return nil, reject("Invalid module archive")
	}
	if err = identifier(declaration.Root); err != nil {
		return nil, err
	}
	result := &bundle{root: declaration.Root, manifests: Registry{}, files: files}
	consumed := map[string]bool{"bundle.json": true}
	for _, name := range names(files) {
		if !manifestPathPattern.MatchString(name) {
			continue
		}
		manifestRaw, err := archiveBytes(files[name], 256<<10)
		if err != nil {
			return nil, err
		}
		manifest, err := decodeManifest(manifestRaw)
		if err != nil {
			return nil, err
		}
		id := text(manifest, "id")
		if err = identifier(id); err != nil {
			return nil, err
		}
		prefix := "modules/" + id + "/"
		if name != prefix+"manifest.json" {
			return nil, reject("Identifier does not match directory")
		}
		signer := text(manifest, "signer")
		if !signerPattern.MatchString(signer) {
			return nil, reject("Publisher not specified")
		}
		public, err := key(signer)
		if err != nil {
			return nil, err
		}
		signature, err := archiveBytes(files[prefix+"signature"], ed25519.SignatureSize)
		if err != nil || len(signature) != ed25519.SignatureSize || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, manifestRaw, signature) {
			return nil, reject("Invalid module signature: " + id)
		}
		if err = validateManifest(manifest, core, architecture, true); err != nil {
			return nil, err
		}
		consumed[name], consumed[prefix+"signature"] = true, true
		payload, _ := object(manifest, "files")
		for _, relative := range names(payload) {
			file := files[prefix+relative]
			if file == nil {
				return nil, reject("Corrupted file: " + relative)
			}
			if err = verifyArchiveFile(file, payload[relative].(string)); err != nil {
				return nil, err
			}
			consumed[prefix+relative] = true
		}
		result.manifests[id] = manifest
	}
	if len(consumed) != len(files) || result.manifests[result.root] == nil {
		return nil, reject("Archive contains unknown files or is missing its root module")
	}
	return result, nil
}

func readPublicKey(directory, signer string, trustedUID uint32) (ed25519.PublicKey, error) {
	if !signerPattern.MatchString(signer) {
		return nil, reject("Publisher not specified")
	}
	dir, err := trustedDirectory(directory, trustedUID)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), signer+".pem", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, reject("Unknown publisher: " + signer)
	}
	file := os.NewFile(uintptr(fd), "module public key")
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != trustedUID || st.Nlink != 1 || info.Mode().Perm()&0022 != 0 {
		return nil, reject("Module signing key permissions are unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(raw) > 8192 {
		return nil, reject("Invalid module signing key")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, reject("Invalid module signing key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, reject("Invalid module signing key")
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, reject("Invalid module signing key")
	}
	return public, nil
}

func decodeRegistry(raw []byte) (Registry, error) {
	if len(raw) > 8<<20 {
		return nil, reject("Module registry is too large")
	}
	var result Registry
	if err := systemops.Decode(raw, &result); err != nil || result == nil {
		return nil, reject("Module registry could not be read; preserve it and review recovery")
	}
	for id, manifest := range result {
		if identifier(id) != nil || text(manifest, "id") != id {
			return nil, reject("Module registry contains an invalid identity")
		}
	}
	return result, nil
}
