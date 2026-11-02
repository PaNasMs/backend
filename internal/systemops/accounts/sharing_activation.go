package accounts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"panasms.local/backend/internal/systemops"
)

const sharingConfigurationUntrusted = "Sharing configuration cannot be trusted. Ask an administrator to check its ownership and permissions."
const sharingActivationChanged = "Sharing changed during the system update. Current files were preserved; review the update before retrying."
const sharingActivationRequired = "Install the compatibility update in System updates before continuing."
const sharingActivationPending = "Sharing setup is incomplete. Finish the system update before continuing."
const sharingRestorePending = "Sharing rollback is incomplete. Recover the system update before continuing."

type sharingActivationSource struct {
	Fresh          bool   `json:"fresh,omitempty"`
	Schema         int    `json:"schema,omitempty"`
	PackageVersion string `json:"packageVersion,omitempty"`
	PairedRestore  int    `json:"pairedRestore,omitempty"`
	Native         bool   `json:"native,omitempty"`
}
type sharingActivationTicket struct {
	Schema        int                            `json:"schema"`
	TargetVersion string                         `json:"targetVersion"`
	Nonce         string                         `json:"nonce"`
	Source        sharingActivationSource        `json:"source"`
	Files         map[string]sharingFileSnapshot `json:"files"`
	Previous      *sharingActivationTicket       `json:"previous,omitempty"`
}
type sharingActivationReceipt struct {
	Schema         int                     `json:"schema"`
	PackageVersion string                  `json:"packageVersion"`
	Nonce          string                  `json:"nonce"`
	Source         sharingActivationSource `json:"source"`
}

func (entry *sharingFileSnapshot) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	var exists *bool
	if err := json.Unmarshal(fields["exists"], &exists); err != nil {
		return err
	}
	if exists == nil {
		return reject(sharingActivationPending)
	}
	entry.Exists = *exists
	if !entry.Exists {
		if len(fields) != 1 {
			return reject(sharingActivationPending)
		}
		*entry = sharingFileSnapshot{}
		return nil
	}
	if len(fields) != 5 || len(fields["data"]) == 0 || fields["data"][0] != '"' {
		return reject(sharingActivationPending)
	}
	var encoded string
	if err := json.Unmarshal(fields["data"], &encoded); err != nil {
		return err
	}
	var err error
	entry.Data, err = base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	for name, target := range map[string]*uint32{"mode": &entry.Mode, "uid": &entry.UID, "gid": &entry.GID} {
		var value *uint32
		if err = json.Unmarshal(fields[name], &value); err != nil {
			return err
		}
		if value == nil {
			return reject(sharingActivationPending)
		}
		*target = *value
	}
	if entry.Mode > 0777 || entry.Mode&0022 != 0 {
		return reject(sharingActivationPending)
	}
	return nil
}

func sharingNonce(value string) bool {
	_, err := hex.DecodeString(value)
	return len(value) == 32 && err == nil
}
func sharingSourceValid(source sharingActivationSource) bool {
	if source.Fresh {
		return source.Schema == 0 && source.PackageVersion == "" && source.PairedRestore == 0 && !source.Native
	}
	return source.Schema == 1 && source.PackageVersion != "" && source.PairedRestore == 1
}
func (s *sharingService) metadata(path string, target any) (bool, error) {
	entry, err := s.fileSnapshot(path)
	if err != nil || !entry.Exists {
		return false, err
	}
	if entry.Mode != 0600 {
		return false, reject(sharingActivationPending)
	}
	if err = sharingDecodeMetadata(entry.Data, target); err != nil {
		return false, err
	}
	return true, nil
}
func (s *sharingService) validTicket(ticket *sharingActivationTicket) error {
	if ticket.Schema != 1 || ticket.TargetVersion == "" || !sharingNonce(ticket.Nonce) || !sharingSourceValid(ticket.Source) || len(ticket.Files) != 4 || ticket.Previous != nil && ticket.Previous.Previous != nil {
		return reject(sharingActivationPending)
	}
	for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
		entry, ok := ticket.Files[path]
		if !ok || entry.Exists && (int(entry.UID) != s.ownerUID || ticket.Source.Fresh) {
			return reject(sharingActivationPending)
		}
	}
	return nil
}
func (s *sharingService) requireNativeSharing(ctx context.Context, mode string) error {
	version, err := s.packageVersion(ctx)
	if err != nil {
		return reject(sharingActivationRequired)
	}
	s.pendingRollback = false
	var receipt sharingActivationReceipt
	present, err := s.metadata(s.activationReceipt, &receipt)
	if err != nil {
		return reject(sharingActivationRequired)
	}
	var ticket sharingActivationTicket
	pending, err := s.metadata(s.activationTicket, &ticket)
	if err != nil {
		return reject(sharingActivationPending)
	}
	authorized := present && receipt.Schema == 1 && receipt.PackageVersion == version && sharingNonce(receipt.Nonce) && sharingSourceValid(receipt.Source)
	if pending && (s.validTicket(&ticket) != nil || ticket.TargetVersion != version || ticket.Nonce != receipt.Nonce || ticket.Source != receipt.Source) {
		authorized = false
	}
	if !authorized {
		if !pending || s.validTicket(&ticket) != nil || ticket.TargetVersion != version || ticket.Source.Fresh || (mode != "rollback-check" && mode != "prepare-downgrade") {
			return reject(sharingActivationRequired)
		}
		if mode == "rollback-check" && !sharingFileMapsEqual(s.rollbackSource, ticket.Files) {
			return reject(sharingActivationPending)
		}
		if _, err = s.pendingActivationFiles(ticket); err != nil {
			return err
		}
		s.pendingRollback = true
	}
	guard, err := s.fileSnapshot(s.restoreGuard)
	if err != nil {
		return reject(sharingRestorePending)
	}
	if guard.Exists {
		var value struct {
			Schema            int                            `json:"schema"`
			Transaction       string                         `json:"transaction"`
			Phase             string                         `json:"phase"`
			SourceHash        string                         `json:"sourceHash"`
			Witness           map[string]sharingFileSnapshot `json:"witness"`
			Source            map[string]sharingFileSnapshot `json:"source"`
			SourceActivation  map[string]sharingFileSnapshot `json:"sourceActivation"`
			WitnessActivation map[string]sharingFileSnapshot `json:"witnessActivation"`
		}
		if err = json.Unmarshal(guard.Data, &value); err != nil || guard.Mode != 0600 || mode != "prepare-downgrade" || value.Schema != 1 || value.Phase != "prepared" || value.Transaction == "" || value.Transaction != os.Getenv("PANASMS_UPDATE_TRANSACTION") {
			return reject(sharingRestorePending)
		}
		if len(value.SourceActivation) != 2 || len(value.WitnessActivation) != 2 {
			return reject(sharingRestorePending)
		}
		for _, path := range []string{s.activationReceipt, s.activationTicket} {
			source, ok := value.SourceActivation[path]
			before, known := value.WitnessActivation[path]
			if !ok || !known || source.Exists && int(source.UID) != s.ownerUID || before.Exists && int(before.UID) != s.ownerUID {
				return reject(sharingRestorePending)
			}
			current, e := s.fileSnapshot(path)
			if e != nil || !sharingSnapshotsEqual(current, before) {
				return reject(sharingRestorePending)
			}
		}
		if s.pendingRollback && !sharingFileMapsEqual(value.Source, ticket.Files) {
			return reject(sharingRestorePending)
		}
		if _, e := hex.DecodeString(value.SourceHash); e != nil || len(value.SourceHash) != 64 || len(value.Witness) != 4 || len(value.Source) != 4 {
			return reject(sharingRestorePending)
		}
		for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
			before, ok := value.Witness[path]
			source, sourceOK := value.Source[path]
			if !ok || !sourceOK || before.Exists && int(before.UID) != s.ownerUID || source.Exists && int(source.UID) != s.ownerUID {
				return reject(sharingRestorePending)
			}
			current, e := s.fileSnapshot(path)
			if e != nil {
				return reject(sharingRestorePending)
			}
			if sharingSnapshotsEqual(current, before) {
				continue
			}
			if path == s.smb && before.Exists {
				before.Data = bytes.ReplaceAll(before.Data, []byte("root preexec = /usr/lib/panasms/panasms-system-helper sharing check "), []byte("root preexec = /usr/bin/python3 /usr/lib/panasms/management/sharing.py --check "))
				if sharingSnapshotsEqual(current, before) {
					continue
				}
			}
			return reject(sharingRestorePending)
		}
	} else if s.pendingRollback && mode == "prepare-downgrade" {
		return reject(sharingRestorePending)
	}
	return nil
}

func (s *sharingService) ticketFilesEqual(ticket sharingActivationTicket) (bool, error) {
	for path, before := range ticket.Files {
		current, err := s.fileSnapshot(path)
		if err != nil {
			return false, err
		}
		if !sharingSnapshotsEqual(current, before) {
			return false, nil
		}
	}
	return true, nil
}
func (s *sharingService) activateSharing(ctx context.Context) error {
	if guard, e := sharingExists(s.restoreGuard); e != nil || guard {
		return reject(sharingRestorePending)
	}
	var ticket sharingActivationTicket
	present, err := s.metadata(s.activationTicket, &ticket)
	if err != nil {
		return err
	}
	version, err := s.packageVersion(ctx)
	if err != nil {
		return err
	}
	var receipt sharingActivationReceipt
	committed, err := s.metadata(s.activationReceipt, &receipt)
	if err != nil {
		return err
	}
	if !present {
		if committed && receipt.Schema == 1 && receipt.PackageVersion == version && sharingNonce(receipt.Nonce) && sharingSourceValid(receipt.Source) {
			return nil
		}
		return reject(sharingActivationRequired)
	}
	if err = s.validTicket(&ticket); err != nil || ticket.TargetVersion != version {
		return reject(sharingActivationPending)
	}
	if committed && receipt.Schema == 1 && receipt.PackageVersion == version && receipt.Nonce == ticket.Nonce && receipt.Source == ticket.Source && sharingSourceValid(receipt.Source) {
		return removeSharingFile(s.activationTicket)
	}
	guard, err := sharingExists(s.restoreGuard)
	if err != nil || guard {
		return reject(sharingRestorePending)
	}
	for _, path := range []string{s.journal, filepath.Join(filepath.Dir(s.journal), "sharing-legacy-nfs-transaction.json")} {
		if pending, e := sharingExists(path); e != nil || pending {
			return reject(sharingPending)
		}
	}
	unlock, err := s.lockSharing(ctx, false, false)
	if err != nil {
		return err
	}
	defer unlock()
	if guard, e := sharingExists(s.restoreGuard); e != nil || guard {
		return reject(sharingRestorePending)
	}
	for _, path := range []string{s.journal, filepath.Join(filepath.Dir(s.journal), "sharing-legacy-nfs-transaction.json")} {
		if pending, e := sharingExists(path); e != nil || pending {
			return reject(sharingPending)
		}
	}
	if err = s.authorizeTarget(ctx, version); err != nil {
		return err
	}
	var baseline sharingState
	if ticket.Files[s.state].Exists {
		if err = systemops.Decode(ticket.Files[s.state].Data, &baseline); err != nil {
			return err
		}
	}
	if !s.knownSharingConfig(ticket.Files, baseline) {
		return reject(sharingDrift)
	}
	seeded, err := s.activationSeed(ticket)
	if err != nil {
		return err
	}
	if _, err = s.pendingActivationFiles(ticket); err != nil {
		return err
	}
	if err = s.write(s.state, string(seeded), 0600); err != nil {
		return err
	}
	receipt = sharingActivationReceipt{1, version, ticket.Nonce, ticket.Source}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if err = s.write(s.activationReceipt, string(raw), 0600); err != nil {
		return err
	}
	return removeSharingFile(s.activationTicket)
}

func (s *sharingService) abortSharingActivation(ctx context.Context) error {
	var ticket sharingActivationTicket
	present, err := s.metadata(s.activationTicket, &ticket)
	if err != nil || !present {
		return err
	}
	if err = s.validTicket(&ticket); err != nil || !ticket.Source.Native {
		return reject(sharingActivationPending)
	}
	version, err := s.packageVersion(ctx)
	if err != nil || version != ticket.Source.PackageVersion {
		return reject(sharingActivationPending)
	}
	var receipt sharingActivationReceipt
	committed, err := s.metadata(s.activationReceipt, &receipt)
	if err != nil || !committed || receipt.Schema != 1 || receipt.PackageVersion != version || !sharingNonce(receipt.Nonce) || receipt.Nonce == ticket.Nonce || !sharingSourceValid(receipt.Source) {
		return reject(sharingActivationPending)
	}
	if guard, e := sharingExists(s.restoreGuard); e != nil || guard {
		return reject(sharingRestorePending)
	}
	unlock, err := s.lockSharing(ctx, false, false)
	if err != nil {
		return err
	}
	defer unlock()
	for _, path := range []string{s.journal, filepath.Join(filepath.Dir(s.journal), "sharing-legacy-nfs-transaction.json")} {
		if pending, e := sharingExists(path); e != nil || pending {
			return reject(sharingPending)
		}
	}
	if equal, err := s.ticketFilesEqual(ticket); err != nil || !equal {
		return reject(sharingActivationPending)
	}
	if ticket.Previous != nil {
		if s.validTicket(ticket.Previous) != nil || ticket.Previous.TargetVersion != version || ticket.Previous.Nonce != receipt.Nonce || ticket.Previous.Source != receipt.Source {
			return reject(sharingActivationPending)
		}
		raw, err := json.Marshal(ticket.Previous)
		if err != nil {
			return err
		}
		return s.write(s.activationTicket, string(raw), 0600)
	}
	return removeSharingFile(s.activationTicket)
}

func sharingVersion(ctx context.Context) (string, error) {
	raw, err := systemops.Command(ctx, []string{"dpkg-query", "-W", "-f=${Version}", "panasms-prototype"}, systemops.CommandOptions{})
	if err != nil || strings.TrimSpace(string(raw)) == "" {
		return "", reject(sharingActivationRequired)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (s *sharingService) requireSharingTarget(ctx context.Context, version string) error {
	raw, err := s.run(ctx, []string{"/usr/bin/python3", "/usr/lib/panasms/management/sharing_compat.py", "target-capabilities"}, systemops.CommandOptions{})
	if err != nil {
		return reject(sharingActivationRequired)
	}
	var proof struct {
		Schema         int    `json:"schema"`
		PackageVersion string `json:"packageVersion"`
		PairedRestore  int    `json:"pairedRestore"`
	}
	if err = sharingDecodeMetadata(raw, &proof); err != nil || proof.Schema != 1 || proof.PackageVersion != version || proof.PairedRestore != 1 {
		return reject(sharingActivationRequired)
	}
	return nil
}

func sharingDecodeMetadata(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return reject(sharingActivationPending)
	}
	return nil
}

func sharingFileMapsEqual(left, right map[string]sharingFileSnapshot) bool {
	if len(left) != 4 || len(right) != 4 {
		return false
	}
	for path, before := range left {
		after, ok := right[path]
		if !ok || !sharingSnapshotsEqual(before, after) {
			return false
		}
	}
	return true
}
func (s *sharingService) activationSeed(ticket sharingActivationTicket) ([]byte, error) {
	st := sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}}
	if ticket.Files[s.state].Exists {
		if err := systemops.Decode(ticket.Files[s.state].Data, &st); err != nil {
			return nil, err
		}
	}
	if err := validateSharingState(st); err != nil {
		return nil, err
	}
	revision := sharingSnapshotRevision(ticket.Files[s.legacy])
	if ticket.Source.Native && st.LegacyExportRevision != revision {
		return nil, reject(sharingLegacyDrift)
	}
	st.LegacyExportRevision = revision
	return json.Marshal(st)
}
func (s *sharingService) pendingActivationFiles(ticket sharingActivationTicket) (map[string]sharingFileSnapshot, error) {
	for _, path := range []string{s.journal, filepath.Join(filepath.Dir(s.journal), "sharing-legacy-nfs-transaction.json")} {
		if exists, err := sharingExists(path); err != nil || exists {
			return nil, reject(sharingPending)
		}
	}
	seeded, err := s.activationSeed(ticket)
	if err != nil {
		return nil, err
	}
	files := map[string]sharingFileSnapshot{}
	for path, before := range ticket.Files {
		current, err := s.fileSnapshot(path)
		if err != nil {
			return nil, err
		}
		if !sharingSnapshotsEqual(current, before) {
			if path != s.state || !current.Exists || current.Mode != 0600 || !bytes.Equal(current.Data, seeded) {
				return nil, reject(sharingActivationChanged)
			}
			var parent unix.Stat_t
			if err := unix.Lstat(filepath.Dir(s.state), &parent); err != nil {
				return nil, err
			}
			gid := uint32(os.Getegid())
			if parent.Mode&unix.S_ISGID != 0 {
				gid = parent.Gid
			}
			if current.GID != gid {
				return nil, reject(sharingActivationChanged)
			}
		}
		files[path] = current
	}
	return files, nil
}
