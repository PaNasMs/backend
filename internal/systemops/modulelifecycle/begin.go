package modulelifecycle

import (
	"crypto/rand"
	"encoding/hex"
	"os"

	"golang.org/x/sys/unix"
)

func installationID(before Manifest) (string, error) {
	value, present := before["installation"]
	if present && value != "" && value != nil {
		id, valid := value.(string)
		if !valid || !uploadToken.MatchString(id) {
			return "", reject("Installed module identity is invalid; preserve it for inspection")
		}
		return id, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(nonce[:]), nil
}

func (s lifecycle) transactionFor(action string, plan *prepared) (*transaction, error) {
	before, err := copyRegistry(plan.installed)
	if err != nil {
		return nil, err
	}
	after, err := copyRegistry(plan.installed)
	if err != nil {
		return nil, err
	}
	state := &transaction{Schema: 1, Phase: "staging", Before: before, After: after, Affected: append([]string{}, plan.order...), Units: map[string]fileSnapshot{}, Candidates: map[string]fileSnapshot{}, Payloads: map[string]payloadState{}}
	for _, id := range plan.order {
		state.Units[id] = plan.units[id]
		state.Payloads[id] = plan.payloads[id]
		switch action {
		case "module.remove":
			delete(after, id)
		case "module.disable":
			after[id]["enabled"] = false
		default:
			manifest := plan.available[id]
			if manifest == nil {
				manifest = before[id]
			}
			copy, err := copyRegistry(Registry{id: manifest})
			if err != nil {
				return nil, err
			}
			effective := copy[id]
			effective["enabled"] = !(action == "module.install" && id == plan.target && before[id] != nil && before[id]["enabled"] == false)
			effective["installation"], err = installationID(before[id])
			if err != nil {
				return nil, err
			}
			after[id] = effective
		}
		candidate := state.Units[id]
		if action == "module.remove" {
			candidate = fileSnapshot{}
		} else if action != "module.disable" && text(after[id], "service") != "" {
			content, err := unitContent(s.root, after[id])
			if err != nil {
				return nil, err
			}
			candidate = fileSnapshot{Exists: true, Data: content, Mode: 0644, UID: s.owner, GID: uint32(os.Getegid())}
		}
		state.Candidates[id] = candidate
	}
	if err = state.validate(s.owner); err != nil {
		return nil, err
	}
	return state, nil
}

func (s lifecycle) begin(action string, plan *prepared) (*transaction, error) {
	state, err := s.transactionFor(action, plan)
	if err != nil {
		return nil, err
	}
	root, err := trustedDirectory(s.root, s.owner)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if err = unix.Mkdirat(int(root.Fd()), ".transaction", 0700); err != nil {
		return nil, err
	}
	if err = root.Sync(); err != nil {
		return state, err
	}
	return state, s.saveTransaction(state)
}
