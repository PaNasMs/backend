package accounts

import (
	"context"
	"encoding/json"
	"io"

	"panasms.local/backend/internal/systemops"
)

func SharingCommand(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	return defaultSharing().cli(ctx, args, input, output)
}
func (s *sharingService) cli(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) == 2 && args[0] == "check" {
		if err := s.authorizeNative(ctx, "check"); err != nil {
			return err
		}
		st, err := s.read()
		if err != nil {
			return err
		}
		for _, share := range st.Shares {
			if share.Name == args[1] {
				return s.check(ctx, share)
			}
		}
		return reject("Shared volume unavailable")
	}
	if len(args) == 2 && args[0] == "rollback-check" && args[1] == "--source" {
		raw, err := io.ReadAll(io.LimitReader(input, 1024*1024+1))
		if err != nil || len(raw) > 1024*1024 {
			return reject("Request too large")
		}
		var request struct {
			Schema int                            `json:"schema"`
			Source map[string]sharingFileSnapshot `json:"source"`
		}
		if err = sharingDecodeMetadata(raw, &request); err != nil || request.Schema != 1 || len(request.Source) != 4 {
			return reject(sharingActivationPending)
		}
		s.rollbackSource = request.Source
		args = args[:1]
	}
	if len(args) != 1 {
		return reject("Unknown sharing operation")
	}
	var result any = map[string]any{}
	switch args[0] {
	case "activate":
		if err := s.activateSharing(ctx); err != nil {
			return err
		}
	case "abort-activation":
		if err := s.abortSharingActivation(ctx); err != nil {
			return err
		}
	case "rollback-check":
		witness, err := s.rollbackWitness(ctx)
		if err != nil {
			return err
		}
		result = witness
	case "sync":
		raw, err := io.ReadAll(io.LimitReader(input, 1024*1024+1))
		if err != nil || len(raw) > 1024*1024 {
			return reject("Request too large")
		}
		var request struct {
			User     string `json:"user"`
			Password string `json:"password"`
		}
		if err = systemops.Decode(raw, &request); err != nil {
			return reject("Invalid SMB synchronization request")
		}
		if _, err = s.dependency(ctx, "sync-password", request.User, request.Password); err != nil {
			return reject("SMB password synchronization failed; see Users → Security")
		}
	case "remove-shares":
		raw, err := io.ReadAll(io.LimitReader(input, 1024*1024+1))
		if err != nil || len(raw) > 1024*1024 {
			return reject("Request too large")
		}
		var names []string
		if err = systemops.Decode(raw, &names); err != nil {
			return reject("Invalid sharing request")
		}
		for _, name := range names {
			if !shareName(name) {
				return reject("Invalid sharing request")
			}
		}
		removed, err := s.removeShares(ctx, names)
		if err != nil {
			return err
		}
		result = removed
	case "install":
		unlock, err := s.locked()
		if err != nil {
			return err
		}
		defer unlock()
		if err = s.install(ctx); err != nil {
			return err
		}
	case "uninstall":
		unlock, err := s.locked()
		if err != nil {
			return err
		}
		defer unlock()
		if err = s.removeInstallation(); err != nil {
			return err
		}
	case "recover", "reconcile", "republish", "remove", "prepare-downgrade":
		s.guardMode = args[0]
		unlock, err := s.lockedContext(ctx, args[0] == "recover" || args[0] == "prepare-downgrade")
		if err != nil {
			return err
		}
		defer unlock()
		switch args[0] {
		case "prepare-downgrade":
			if err = s.prepareDowngrade(ctx); err != nil {
				return err
			}
		case "recover":
			pending, err := sharingExists(s.journal)
			if err != nil {
				return err
			}
			if pending {
				if err = s.recover(ctx, nil); err != nil {
					return err
				}
				if err = s.republish(ctx); err != nil {
					return err
				}
			}
		case "republish":
			if err = s.republish(ctx); err != nil {
				return err
			}
		case "reconcile":
			if err = s.reconcile(ctx); err != nil {
				return err
			}
		case "remove":
			st, err := s.read()
			if err != nil {
				return err
			}
			for username := range st.Accounts {
				if err = s.disable(ctx, username, nil); err != nil {
					return err
				}
			}
			for _, path := range []string{s.smb, s.exports} {
				if err = removeSharingFile(path); err != nil {
					return err
				}
			}
			if err = s.reload(ctx, nil, nil); err != nil {
				return err
			}
		}
	default:
		return reject("Unknown sharing operation")
	}
	return json.NewEncoder(output).Encode(result)
}
