package luks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

const managedConfigDir = "/etc/panasms/luks"
const crypttabPath = "/etc/crypttab"

var luksUUIDPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type luksMetadata struct {
	UUID               string
	HeaderDigest       string
	RestoreIdentity    string
	Slots, UsableSlots []int
}

type managedConfig struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	Slot int    `json:"slot"`
}

func readLUKSMetadata(ctx context.Context, path string) (luksMetadata, error) {
	raw, err := systemops.Command(ctx, []string{"cryptsetup", "luksUUID", path}, systemops.CommandOptions{})
	if err != nil {
		return luksMetadata{}, err
	}
	uuid := strings.TrimSpace(string(raw))
	if !luksUUIDPattern.MatchString(uuid) {
		return luksMetadata{}, reject("Invalid LUKS UUID")
	}
	raw, err = systemops.Command(ctx, []string{"cryptsetup", "luksDump", "--dump-json-metadata", path}, systemops.CommandOptions{})
	if err != nil {
		if _, v1err := systemops.Command(ctx, []string{"cryptsetup", "isLuks", "--type", "luks1", path}, systemops.CommandOptions{}); v1err == nil {
			return luksMetadata{}, reject("Key management, boot unlocking and header backups require LUKS2. This LUKS1 volume can be opened and closed.")
		}
		return luksMetadata{}, err
	}
	return parseLUKSMetadata(uuid, raw)
}

type volumeDigest struct {
	Type       string
	Hash       string
	Iterations uint64
	Salt       string
	Digest     string
}

type luksSegment struct {
	Type       string
	Offset     string
	Size       string
	IVTweak    string `json:"iv_tweak"`
	Encryption string
	SectorSize uint64 `json:"sector_size"`
	Integrity  json.RawMessage
	Flags      []string
}

func parseLUKSMetadata(uuid string, data []byte) (luksMetadata, error) {
	var header struct {
		Keyslots map[string]struct{ Type string } `json:"keyslots"`
		Digests  map[string]struct {
			volumeDigest
			Keyslots, Segments []string
		} `json:"digests"`
		Segments map[string]luksSegment `json:"segments"`
	}
	invalid := reject("Invalid LUKS2 header metadata")
	if json.Unmarshal(data, &header) != nil || header.Keyslots == nil || header.Digests == nil || len(header.Segments) == 0 {
		return luksMetadata{}, invalid
	}
	// A slot can be replaced without changing its number. Bind plans to the
	// metadata, including digests and salts, without returning it in query output.
	sum := sha256.Sum256(data)
	result := luksMetadata{UUID: uuid, HeaderDigest: hex.EncodeToString(sum[:]), Slots: []int{}, UsableSlots: []int{}}
	bound := map[string]bool{}
	// Keyslot enrollment changes the slot list attached to a digest, while
	// the digest of the volume key and the data encryption geometry persist.
	segment := header.Segments["0"]
	normalSegment := len(header.Segments) == 1 && segment.Type == "crypt"
	comparable := normalSegment && segment.Encryption != "" && segment.Offset != "" && segment.Size != "" && segment.IVTweak != "" && segment.SectorSize > 0
	var digestIDs []string
	for _, digest := range header.Digests {
		for _, id := range digest.Segments {
			if _, ok := header.Segments[id]; !ok {
				return luksMetadata{}, invalid
			}
		}
		onData := normalSegment && slices.Contains(digest.Segments, "0")
		if onData {
			// Unknown digest types cannot be safely compared using PBKDF2 fields.
			if digest.Type != "pbkdf2" || digest.Hash == "" || digest.Iterations == 0 || digest.Salt == "" || digest.Digest == "" {
				comparable = false
			} else {
				encoded, err := json.Marshal(digest.volumeDigest)
				if err != nil {
					return luksMetadata{}, err
				}
				digestIDs = append(digestIDs, string(encoded))
			}
		}
		for _, id := range digest.Keyslots {
			slot, ok := header.Keyslots[id]
			if !ok {
				return luksMetadata{}, invalid
			}
			// Only count standard keys for a normal single-segment encrypted volume.
			// Unbound or reencryption slots cannot establish another working password.
			if slot.Type == "luks2" && onData {
				bound[id] = true
			}
		}
	}
	if comparable && len(digestIDs) > 0 {
		slices.Sort(digestIDs)
		encoded, err := json.Marshal(struct {
			Segment luksSegment
			Digests []string
		}{segment, digestIDs})
		if err != nil {
			return luksMetadata{}, err
		}
		sum := sha256.Sum256(encoded)
		result.RestoreIdentity = hex.EncodeToString(sum[:])
	}
	for key := range header.Keyslots {
		id, err := strconv.Atoi(key)
		if err != nil || id < 0 || id >= 32 || strconv.Itoa(id) != key {
			return luksMetadata{}, invalid
		}
		result.Slots = append(result.Slots, id)
		if bound[key] {
			result.UsableSlots = append(result.UsableSlots, id)
		}
	}
	slices.Sort(result.Slots)
	slices.Sort(result.UsableSlots)
	return result, nil
}

// Read on the opened descriptor. Never follow a symbolic link or block on a FIFO.
func readConfigFile(path string, limit int64) ([]byte, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0022 != 0 {
		return nil, reject("Unsafe LUKS configuration file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, reject("LUKS configuration file is too large")
	}
	return data, nil
}

func readManagedConfig(uuid string) (*managedConfig, error) {
	if !luksUUIDPattern.MatchString(uuid) {
		return nil, reject("Invalid LUKS UUID")
	}
	if err := storagebase.SecureDirectory(managedConfigDir, 0, false); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	data, err := readConfigFile(filepath.Join(managedConfigDir, uuid+".json"), 64<<10)
	if data == nil || err != nil {
		return nil, err
	}
	return parseManagedConfig(uuid, data)
}

func parseManagedConfig(uuid string, data []byte) (*managedConfig, error) {
	var stored struct {
		UUID, Name string
		Slot       *int
	}
	if json.Unmarshal(data, &stored) == nil && stored.UUID == uuid && stored.Slot != nil && *stored.Slot >= 0 && *stored.Slot < 32 {
		if _, err := systemops.Name(stored.Name); err == nil {
			return &managedConfig{uuid, stored.Name, *stored.Slot}, nil
		}
	}
	return nil, reject("Invalid managed LUKS configuration")
}

func readCrypttab() ([]string, error) {
	data, err := readConfigFile(crypttabPath, systemops.MaxOutput)
	if err != nil {
		return nil, err
	}
	return splitCrypttab(string(data)), nil
}

func queryResult(path string, metadata luksMetadata, config *managedConfig, lines []string) (json.RawMessage, error) {
	var slot *int
	automatic := false
	if config != nil {
		slot = &config.Slot
		if config.UUID == metadata.UUID && slices.Contains(metadata.UsableSlots, config.Slot) {
			_, found, err := inspectCrypttab(lines, metadata.UUID, config, config.Name)
			automatic = found && err == nil
		}
	}
	return json.Marshal(map[string]any{"target": path, "uuid": metadata.UUID, "slots": metadata.Slots, "managedSlot": slot, "automatic": automatic})
}

func Query(ctx context.Context, target string) (json.RawMessage, error) {
	path, err := canonicalTarget(map[string]any{"target": target})
	if err != nil {
		return nil, err
	}
	p, err := storagequery.LoadPreflight(ctx)
	if err != nil {
		return nil, err
	}
	if err = p.Protected(path, false); err != nil {
		return nil, err
	}
	if p.Inventory.Rows[path]["fstype"] != "crypto_LUKS" {
		return nil, reject("Select a LUKS container")
	}
	identity, err := p.Identity(path)
	if err != nil {
		return nil, err
	}
	pinned, err := pinIdentity(identity, path)
	if err != nil {
		return nil, err
	}
	defer pinned.Close()
	metadata, err := readLUKSMetadata(ctx, pinned.Path())
	if err != nil {
		return nil, err
	}
	if pinned.Identity.UUID != "" && !strings.EqualFold(pinned.Identity.UUID, metadata.UUID) {
		return nil, reject("The LUKS volume changed. Refresh the device list.")
	}
	config, err := readManagedConfig(metadata.UUID)
	if err != nil {
		return nil, err
	}
	var lines []string
	if config != nil {
		lines, err = readCrypttab()
		if err != nil {
			return nil, err
		}
	}
	if err = pinned.Verify(); err != nil {
		return nil, err
	}
	return queryResult(path, metadata, config, lines)
}

func pinIdentity(identity storagequery.StorageIdentity, target string) (*storagebase.PinnedDevice, error) {
	for _, dev := range identity.Devices {
		if dev.Path == target {
			return storagebase.PinDevice(dev)
		}
	}
	return nil, reject("Could not verify storage identity")
}
