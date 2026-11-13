package luks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"panasms.local/backend/internal/auth"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"panasms.local/backend/internal/systemops/storagequery"
)

type prepared struct {
	Target, ReadPath, UUID, Name, MappingUUID string
	Actor                                     auth.Identity
	Meta                                      luksMetadata
	Extra                                     any
	pin                                       *storagebase.PinnedDevice
	details                                   []string
	fingerprint                               string
}

func reject(message string) error { return &systemops.Rejected{Message: message} }

func passphrase(params map[string]any, key string) (string, error) {
	s, _ := params[key].(string)
	if s == "" || strings.ContainsRune(s, 0) || utf8.RuneCountInString(s) > 4096 {
		return "", reject("Enter the LUKS password")
	}
	return s, nil
}

func canonicalTarget(params map[string]any) (string, error) {
	input, _ := params["target"].(string)
	if !strings.HasPrefix(input, "/dev/") || filepath.Clean(input) != input {
		return "", reject("Select a block device")
	}
	target, err := filepath.EvalSymlinks(input)
	if err != nil || filepath.Dir(target) != "/dev" {
		return "", reject("The device no longer exists")
	}
	return target, nil
}

func Plan(ctx context.Context, action string, params map[string]any) (json.RawMessage, error) {
	lock, err := storagebase.DomainLock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	p, err := prepare(ctx, action, params)
	if err != nil {
		return nil, err
	}
	defer p.pin.Close()
	return json.Marshal(map[string]any{"target": p.Target, "confirmation": p.Target, "details": p.details, "fingerprint": p.fingerprint})
}

func prepare(ctx context.Context, action string, params map[string]any) (*prepared, error) {
	target, err := canonicalTarget(params)
	if err != nil {
		return nil, err
	}
	pf, err := storagequery.LoadPreflight(ctx)
	if err != nil {
		return nil, err
	}
	if err = pf.Protected(target, false); err != nil {
		return nil, err
	}
	identity, err := pf.Identity(target)
	if err != nil {
		return nil, err
	}
	if err = storagebase.CheckPendingRoots("luks", target, identity); err != nil {
		return nil, err
	}
	pin, err := pinIdentity(identity, target)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			pin.Close()
		}
	}()
	row := pf.Inventory.Rows[target]
	p := &prepared{Target: target, pin: pin, ReadPath: pin.Path(), details: []string{target}}
	if action == "luks.open" || action == "luks.auto-enable" {
		mapping, _ := params["name"].(string)
		p.Name, err = systemops.Name(mapping)
		if err != nil {
			return nil, err
		}
		path := filepath.Join("/dev/mapper", p.Name)
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			dest, resolveErr := filepath.EvalSymlinks(path)
			if err != nil || resolveErr != nil || action != "luks.auto-enable" || !pf.Inventory.Parents[dest][target] {
				return nil, reject("Name already in use")
			}
		}
	}
	if action == "luks.create" || action == "luks.open" || action == "luks.close" || action == "luks.header-restore" {
		if err = pf.Unused(target, false); err != nil {
			return nil, err
		}
	}
	if action == "luks.create" || action == "luks.open" {
		if _, err = passphrase(params, "passphrase"); err != nil {
			return nil, err
		}
	}
	fs, _ := row["fstype"].(string)
	switch action {
	case "luks.create":
		if fs != "" {
			return nil, reject("LUKS requires an empty device")
		}
		if err = checkBlank(ctx, p.ReadPath); err != nil {
			return nil, err
		}
	case "luks.close":
		if row["type"] != "crypt" {
			return nil, reject("Select an unlocked LUKS volume")
		}
		p.Name, _ = row["name"].(string)
		if p.Name == "" || filepath.Base(p.Name) != p.Name || p.Name == "." || p.Name == ".." {
			return nil, reject("Could not verify the mapping name")
		}
		mapping := filepath.Join("/dev/mapper", p.Name)
		current, err := filepath.EvalSymlinks(mapping)
		if err != nil || current != target {
			return nil, reject("The mapping changed. Review a new operation plan.")
		}
		uuid, err := os.ReadFile(filepath.Join("/sys/class/block", filepath.Base(target), "dm/uuid"))
		if err != nil {
			return nil, err
		}
		p.MappingUUID = strings.TrimSpace(string(uuid))
		if p.MappingUUID == "" {
			return nil, reject("Could not verify the encrypted mapping identity")
		}
		p.details = []string{mapping}
	case "luks.open":
		if fs != "crypto_LUKS" {
			return nil, reject("Select a LUKS container")
		}
	case "luks.key-add", "luks.key-remove", "luks.auto-enable", "luks.auto-disable", "luks.header-backup", "luks.header-restore":
		if fs != "crypto_LUKS" {
			return nil, reject("Select a LUKS container")
		}
		p.Meta, err = readLUKSMetadata(ctx, p.ReadPath)
		if err != nil {
			return nil, err
		}
		p.UUID = p.Meta.UUID
		if pin.Identity.UUID != p.UUID {
			return nil, reject("The encrypted volume identity changed. Review a new operation plan.")
		}
		p.Extra, p.details, err = prepareExtra(ctx, action, params, p)
		if err != nil {
			return nil, err
		}
	default:
		return nil, reject("Unknown LUKS operation")
	}
	raw, err := json.Marshal(map[string]any{"identity": identity, "row": row, "name": p.Name, "mappingUUID": p.MappingUUID, "metadata": p.Meta, "extra": p.Extra})
	if err != nil {
		return nil, err
	}
	var state any
	if err = systemops.Decode(raw, &state); err != nil {
		return nil, err
	}
	p.fingerprint, err = systemops.Fingerprint(action, params, state)
	if err != nil {
		return nil, err
	}
	keep = true
	return p, nil
}

func checkBlank(ctx context.Context, path string) error {
	raw, err := systemops.Command(ctx, []string{"wipefs", "--json", "--no-act", "--output", "TYPE,OFFSET", "--", path}, systemops.CommandOptions{})
	if err != nil {
		return err
	}
	var result struct {
		Signatures []json.RawMessage `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &result); err != nil || result.Signatures == nil {
		return reject("Could not verify that the device is empty")
	}
	if len(result.Signatures) != 0 {
		return reject("LUKS requires an empty device")
	}
	return nil
}

func IsAction(action string) bool {
	switch action {
	case "luks.create", "luks.open", "luks.close", "luks.key-add", "luks.key-remove",
		"luks.auto-enable", "luks.auto-disable", "luks.header-backup", "luks.header-restore":
		return true
	}
	return false
}
