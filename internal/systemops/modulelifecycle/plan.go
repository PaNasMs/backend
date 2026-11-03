package modulelifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
	"panasms.local/backend/internal/systemops"
)

type lifecycle struct {
	store
	core, architecture, units, uploads, keys, maintenance, coreFile string
	run                                                             command
	compare                                                         versionCompare
	health                                                          healthCheck
	mounts                                                          func() ([]string, error)
}

type prepared struct {
	installed   Registry
	target      string
	order       []string
	available   Registry
	packages    []string
	archive     *os.File
	bundle      *bundle
	uploadName  string
	fingerprint string
	result      json.RawMessage
	units       map[string]fileSnapshot
	payloads    map[string]payloadState
	signingKeys map[string]ed25519.PublicKey
}

func IsAction(action string) bool {
	switch action {
	case "module.install", "module.enable", "module.disable", "module.remove", "module.recover":
		return true
	}
	return false
}

var uploadToken = regexp.MustCompile(`^[a-f0-9]{32}$`)

func planFingerprint(action string, params map[string]any, identity any) (string, error) {
	raw, err := json.Marshal([]any{params, identity})
	if err != nil {
		return "", err
	}
	var values []any
	if err = systemops.Decode(raw, &values); err != nil {
		return "", err
	}
	return systemops.Fingerprint(action, values[0].(map[string]any), values[1])
}

func (s lifecycle) openUpload(token, name string) (*os.File, string, error) {
	if !uploadToken.MatchString(token) {
		return nil, "", reject("Upload the archive again")
	}
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") {
		return nil, "", reject("Archive not found or belongs to another user")
	}
	dir, err := trustedDirectory(s.uploads, s.owner)
	if err != nil {
		return nil, "", err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), name+"-"+token+".zip", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", reject("Archive not found or belongs to another user")
	}
	file := os.NewFile(uintptr(fd), "verified module upload")
	var before, after unix.Stat_t
	if err = unix.Fstat(fd, &before); err != nil {
		file.Close()
		return nil, "", err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != s.owner || before.Nlink != 1 || before.Mode&0022 != 0 || before.Size <= 0 || before.Size > maxArchive {
		file.Close()
		return nil, "", reject("Module archive ownership or size is unsafe; upload the archive again")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, maxArchive+1))
	if err == nil {
		err = unix.Fstat(fd, &after)
	}
	if err != nil || count != before.Size || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		file.Close()
		return nil, "", reject("Module archive changed while it was read")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		return nil, "", err
	}
	return file, hex.EncodeToString(hash.Sum(nil)), nil
}

func (s lifecycle) plan(ctx context.Context, action string, p map[string]any, name string) (json.RawMessage, error) {
	plan, err := s.prepare(ctx, action, p, name)
	if err != nil {
		return nil, err
	}
	if plan.archive != nil {
		defer plan.archive.Close()
	}
	return plan.result, nil
}

func (s lifecycle) prepare(ctx context.Context, action string, p map[string]any, name string) (result *prepared, err error) {
	if !IsAction(action) {
		return nil, reject("Unknown operation")
	}
	if action == "module.recover" {
		state, err := s.loadTransaction()
		if err != nil {
			return nil, err
		}
		if state == nil {
			return nil, reject("No module transaction needs recovery")
		}
		dir, err := s.transactionDirectory()
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		raw, err := readOwnedAt(dir, "journal.json", s.owner, 16<<20)
		if state.orphan {
			raw = []byte(state.orphanFingerprint)
			err = nil
		}
		if err != nil {
			return nil, err
		}
		fingerprint, err := planFingerprint(action, p, string(raw))
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(map[string]any{"target": "modules", "confirmation": "modules", "details": []string{"Recover the recorded module transaction; installed OS dependencies are retained"}, "fingerprint": fingerprint})
		return &prepared{target: "modules", fingerprint: fingerprint, result: body}, err
	}
	if state, err := s.loadTransaction(); err != nil {
		return nil, err
	} else if state != nil {
		return nil, reject("Recover the recorded module transaction before changing modules")
	}
	installed, err := s.registry()
	if err != nil {
		return nil, err
	}
	plan := &prepared{installed: installed, available: Registry{}, signingKeys: map[string]ed25519.PublicKey{}}
	defer func() {
		if err != nil && plan.archive != nil {
			plan.archive.Close()
		}
	}()
	var identity any = installed
	details := []string{}
	if action == "module.install" {
		token := text(p, "upload")
		file, sum, openErr := s.openUpload(token, name)
		if openErr != nil {
			return nil, openErr
		}
		plan.archive = file
		plan.uploadName = name + "-" + token + ".zip"
		stat, statErr := file.Stat()
		if statErr != nil {
			return nil, statErr
		}
		plan.bundle, err = inspectBundle(file, stat.Size(), s.core, s.architecture, func(signer string) (ed25519.PublicKey, error) {
			key, err := readPublicKey(s.keys, signer, s.owner)
			if err != nil {
				return nil, err
			}
			if previous := plan.signingKeys[signer]; previous != nil && !bytes.Equal(previous, key) {
				return nil, reject("Module publisher trust changed. Review a new operation plan.")
			}
			plan.signingKeys[signer] = append(ed25519.PublicKey{}, key...)
			return key, nil
		})
		if err != nil {
			return nil, err
		}
		plan.target = plan.bundle.root
		plan.available = plan.bundle.manifests
		plan.order, err = resolve(plan.target, plan.available, installed)
		if err != nil {
			return nil, err
		}
		manifests := []Manifest{}
		publishers := map[string]bool{}
		for _, id := range plan.order {
			if err = requireIdle(ctx, installed[id], s.health, s.run); err != nil {
				return nil, err
			}
			manifest := plan.available[id]
			if manifest == nil {
				manifest = installed[id]
			}
			if err = validateManifest(manifest, s.core, s.architecture, plan.available[id] != nil); err != nil {
				return nil, err
			}
			if !signerPattern.MatchString(text(manifest, "signer")) {
				return nil, reject("Publisher not specified")
			}
			manifests = append(manifests, manifest)
			publishers[text(manifest, "signer")] = true
			prefix := "Install/enable: "
			if id == plan.target && installed[id] != nil && installed[id]["enabled"] == false {
				prefix = "Update (remains disabled): "
			}
			details = append(details, prefix+text(manifest, "title")+" "+text(manifest, "version"))
		}
		var changes []string
		plan.packages, changes, err = packagePlan(ctx, manifests, s.run, s.compare)
		if err != nil {
			return nil, err
		}
		for _, change := range changes {
			details = append(details, "OS packages: "+change)
		}
		details = append(details, "Publishers: "+strings.Join(names(publishers), ", "), "The module's server code runs with root privileges. Application operations run with user privileges.")
		identity = []any{installed, sum, plan.packages, changes}
	} else {
		plan.target = text(p, "target")
		if err = identifier(plan.target); err != nil {
			return nil, err
		}
		manifest := installed[plan.target]
		if manifest == nil {
			return nil, reject("Module not installed")
		}
		if action == "module.disable" || action == "module.remove" {
			blockers, err := dependents(plan.target, installed)
			if err != nil {
				return nil, err
			}
			if len(blockers) > 0 {
				return nil, reject("Dependent modules: " + strings.Join(blockers, ", "))
			}
			if err = requireIdle(ctx, manifest, s.health, s.run); err != nil {
				return nil, err
			}
			plan.order = []string{plan.target}
		}
		message := map[string]string{"module.enable": "Enable module and its dependencies", "module.disable": "Disable module", "module.remove": "Remove module code; settings and user files are preserved"}[action]
		details = []string{text(manifest, "title"), message}
		if action == "module.enable" {
			if err = validateManifest(manifest, s.core, s.architecture, false); err != nil {
				return nil, err
			}
			plan.order, err = resolve(plan.target, Registry{}, installed)
			if err != nil {
				return nil, err
			}
			manifests := []Manifest{}
			for _, id := range plan.order {
				if err = validateManifest(installed[id], s.core, s.architecture, false); err != nil {
					return nil, err
				}
				manifests = append(manifests, installed[id])
				details = append(details, "Enable: "+text(installed[id], "title"))
			}
			var changes []string
			plan.packages, changes, err = packagePlan(ctx, manifests, s.run, s.compare)
			if err != nil {
				return nil, err
			}
			for _, change := range changes {
				details = append(details, "OS packages: "+change)
			}
			identity = []any{installed, plan.packages, changes}
		}
	}
	root, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	units, err := trustedDirectory(s.units, s.owner)
	if err != nil {
		return nil, err
	}
	defer units.Close()
	plan.units = map[string]fileSnapshot{}
	plan.payloads = map[string]payloadState{}
	for _, id := range plan.order {
		if err = (recovery{store: s.store, mounts: s.mounts}).noMounts(filepath.Join(s.root, id)); err != nil {
			return nil, err
		}
		plan.units[id], err = snapshotAt(units, unit(id), s.owner)
		if err != nil {
			return nil, err
		}
		payload, err := directoryAt(root, id, s.owner)
		if err != nil {
			return nil, err
		}
		if installed[id] == nil && payload.Exists {
			return nil, reject("Module files exist without an installed receipt; preserve them for inspection")
		}
		if installed[id] == nil && plan.units[id].Exists {
			return nil, reject("Module service exists without an installed receipt; preserve it for inspection")
		}
		plan.payloads[id] = payloadState{Before: payload}
	}
	identity = []any{identity, plan.units, plan.payloads, s.core, s.architecture}
	plan.fingerprint, err = planFingerprint(action, p, identity)
	if err != nil {
		return nil, err
	}
	plan.result, err = json.Marshal(map[string]any{"target": plan.target, "confirmation": plan.target, "details": details, "fingerprint": plan.fingerprint})
	return plan, err
}
