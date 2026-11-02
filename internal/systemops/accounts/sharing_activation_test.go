package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

const fixtureNonce = "0123456789abcdef0123456789abcdef"
const nextFixtureNonce = "fedcba9876543210fedcba9876543210"

func sharingActivationFixture(t *testing.T, fresh bool) (*sharingService, sharingActivationTicket) {
	t.Helper()
	s := sharingFixture(t)
	if !fresh {
		saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{}, Accounts: map[string]*sharedAccount{}})
	}
	ticket := sharingActivationTicket{Schema: 1, TargetVersion: "fixture-native", Nonce: fixtureNonce, Files: map[string]sharingFileSnapshot{}}
	if fresh {
		ticket.Source.Fresh = true
	} else {
		ticket.Source = sharingActivationSource{Schema: 1, PackageVersion: "fixture-prep", PairedRestore: 1}
	}
	for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
		entry, err := s.fileSnapshot(path)
		if err != nil {
			t.Fatal(err)
		}
		ticket.Files[path] = entry
	}
	s.authorizeNative = s.requireNativeSharing
	writeActivationTicket(t, s, ticket)
	return s, ticket
}
func writeActivationTicket(t *testing.T, s *sharingService, ticket sharingActivationTicket) {
	t.Helper()
	raw, err := json.Marshal(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.write(s.activationTicket, string(raw), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSharingActivationPreparedAndFreshInstall(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "fresh"}[fresh], func(t *testing.T) {
			s, ticket := sharingActivationFixture(t, fresh)
			if err := s.requireNativeSharing(context.Background(), "sync"); err == nil {
				t.Fatal("uncommitted ticket authorized a mutation")
			}
			if err := s.cli(context.Background(), []string{"activate"}, nil, io.Discard); err != nil {
				t.Fatal(err)
			}
			if err := s.requireNativeSharing(context.Background(), "sync"); err != nil {
				t.Fatal(err)
			}
			st, err := s.read()
			if err != nil || st.LegacyExportRevision != sharingSnapshotRevision(ticket.Files[s.legacy]) {
				t.Fatal(st, err)
			}
			for _, path := range []string{s.smb, s.exports, s.legacy} {
				current, err := s.fileSnapshot(path)
				if err != nil || !sharingSnapshotsEqual(current, ticket.Files[path]) {
					t.Fatal("activation rewrote protocol files", path, err)
				}
			}
			if pending, _ := sharingExists(s.activationTicket); pending {
				t.Fatal("committed ticket was not consumed")
			}
		})
	}
}

func TestSharingPendingActivationCleanupAndRetry(t *testing.T) {
	for _, fresh := range []bool{false, true} {
		for _, removed := range []string{"", "smb", "nfs"} {
			t.Run(map[bool]string{false: "prepared", true: "fresh"}[fresh]+removed, func(t *testing.T) {
				s, ticket := sharingActivationFixture(t, fresh)
				if !fresh {
					smb, nfs := sharingConfig(nil, true, false)
					s.write(s.smb, smb, 0644)
					s.write(s.exports, nfs, 0644)
					for _, path := range []string{s.smb, s.exports} {
						ticket.Files[path], _ = s.fileSnapshot(path)
					}
					writeActivationTicket(t, s, ticket)
				}
				seed, err := s.activationSeed(ticket)
				if err != nil {
					t.Fatal(err)
				}
				s.write(s.state, string(seed), 0600)
				if removed == "smb" {
					os.Remove(s.smb)
				} else if removed == "nfs" {
					os.Remove(s.exports)
				}
				before, _ := os.ReadFile(s.activationTicket)
				for _, action := range []string{"remove", "remove", "uninstall"} {
					if err = s.cli(context.Background(), []string{action}, nil, io.Discard); err != nil {
						t.Fatal(action, err)
					}
				}
				after, _ := os.ReadFile(s.activationTicket)
				if string(before) != string(after) {
					t.Fatal("cleanup consumed activation evidence")
				}
				if exists, _ := sharingExists(s.activationReceipt); exists {
					t.Fatal("cleanup committed activation")
				}
				if err = s.cli(context.Background(), []string{"republish"}, nil, io.Discard); err == nil {
					t.Fatal("cleanup authorized unrelated mutation")
				}
			})
		}
	}
}

func TestSharingPendingCleanupRefusesForeignFilesBeforeCommands(t *testing.T) {
	for _, changed := range []string{"state", "smb", "nfs", "legacy", "guard", "journal", "legacy-journal", "ticket"} {
		t.Run(changed, func(t *testing.T) {
			s, _ := sharingActivationFixture(t, false)
			paths := map[string]string{"state": s.state, "smb": s.smb, "nfs": s.exports, "legacy": s.legacy, "guard": s.restoreGuard, "journal": s.journal, "legacy-journal": filepath.Join(filepath.Dir(s.journal), "sharing-legacy-nfs-transaction.json"), "ticket": s.activationTicket}
			s.write(paths[changed], "foreign", 0600)
			commands := 0
			s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) {
				commands++
				return nil, nil
			}
			for _, action := range []string{"remove", "uninstall"} {
				if err := s.cli(context.Background(), []string{action}, nil, io.Discard); err == nil {
					t.Fatal("foreign state accepted", action)
				}
			}
			if commands != 0 {
				t.Fatal("foreign state reached a command")
			}
		})
	}
}

func sharingReinstallFixture(t *testing.T) (*sharingService, sharingActivationTicket) {
	t.Helper()
	s, ticket := sharingActivationFixture(t, false)
	ticket.Source.Reinstall = true
	ticket.Source.Native = true
	state := sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}}
	state.LegacyExportRevision = sharingSnapshotRevision(ticket.Files[s.legacy])
	saveSharingFixture(t, s, state)
	ticket.Files[s.state], _ = s.fileSnapshot(s.state)
	for _, path := range []string{s.smb, s.exports} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		ticket.Files[path] = sharingFileSnapshot{}
	}
	ticket.SourceActivation = map[string]sharingFileSnapshot{s.activationReceipt: {}, s.activationTicket: {}}
	writeActivationTicket(t, s, ticket)
	return s, ticket
}

func TestSharingReinstallAcceptsRemovedPublicationsOnlyDuringActivation(t *testing.T) {
	s, ticket := sharingReinstallFixture(t)
	if err := s.requireNativeSharing(context.Background(), "rollback-check"); err == nil {
		t.Fatal("uncommitted reinstall authorized rollback")
	}
	if err := s.activateSharing(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := s.read()
	if err != nil || len(state.Shares) != 1 {
		t.Fatal("retained state lost", state, err)
	}
	for _, path := range []string{s.smb, s.exports, s.legacy} {
		current, _ := s.fileSnapshot(path)
		if !sharingSnapshotsEqual(current, ticket.Files[path]) {
			t.Fatal("activation republished before installation", path)
		}
	}
}

func TestSharingReinstallRefusesForeignPolicyAndMetadata(t *testing.T) {
	for _, change := range []string{"smb", "nfs", "legacy", "receipt", "ticket", "receipt-after-lock"} {
		t.Run(change, func(t *testing.T) {
			s, _ := sharingReinstallFixture(t)
			before, _ := os.ReadFile(s.state)
			if change == "receipt-after-lock" {
				s.authorizeTarget = func(context.Context, string) error {
					return s.write(s.activationReceipt, `{}`, 0600)
				}
			} else {
				path := map[string]string{"smb": s.smb, "nfs": s.exports, "legacy": s.legacy, "receipt": s.activationReceipt, "ticket": s.activationTicket}[change]
				s.write(path, `{}`, 0600)
			}
			if err := s.activateSharing(context.Background()); err == nil {
				t.Fatal("foreign change accepted")
			}
			after, _ := os.ReadFile(s.state)
			if string(before) != string(after) {
				t.Fatal("foreign metadata allowed seed write")
			}
		})
	}
}

func TestSharingEveryMutationRejectsMissingPreparationBeforeWriting(t *testing.T) {
	for _, action := range []string{"install", "uninstall", "recover", "reconcile", "republish", "remove", "prepare-downgrade", "remove-shares", "sync", "check", "rollback-check"} {
		t.Run(action, func(t *testing.T) {
			s := sharingFixture(t)
			s.authorizeNative = s.requireNativeSharing
			writes := 0
			s.write = func(string, string, os.FileMode) error { writes++; return nil }
			args := []string{action}
			input := ""
			if action == "sync" {
				input = `{"user":"alice","password":"fixture-only"}`
			} else if action == "remove-shares" {
				input = `[]`
			} else if action == "check" {
				args = append(args, "Media")
			}
			if err := s.cli(context.Background(), args, strings.NewReader(input), io.Discard); err == nil {
				t.Fatal("missing preparation accepted")
			}
			if writes != 0 {
				t.Fatal("denied operation wrote files")
			}
			if exists, _ := sharingExists(s.lock); exists {
				t.Fatal("denied operation created a lock")
			}
		})
	}
}

func TestSharingActivationMetadataRetryAndForeignChange(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry", true: "foreign"}[foreign], func(t *testing.T) {
			s, _ := sharingActivationFixture(t, false)
			real := s.write
			s.write = func(path, value string, mode os.FileMode) error {
				if path == s.activationReceipt {
					return errors.New("fixture receipt interruption")
				}
				return real(path, value, mode)
			}
			if err := s.activateSharing(context.Background()); err == nil {
				t.Fatal("receipt interruption not observed")
			}
			s.write = real
			if foreign {
				s.write(s.legacy, "foreign NFS grants", 0644)
			}
			err := s.activateSharing(context.Background())
			if (err != nil) != foreign {
				t.Fatal(err)
			}
			if foreign {
				text, _ := sharingText(s.legacy)
				if text != "foreign NFS grants" {
					t.Fatal("foreign legacy file overwritten")
				}
			}
		})
	}
}

func TestSharingStaleSameVersionReceiptCannotBypassReactivation(t *testing.T) {
	s, ticket := sharingActivationFixture(t, false)
	if err := s.activateSharing(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
		ticket.Files[path], _ = s.fileSnapshot(path)
	}
	ticket.Nonce = nextFixtureNonce
	writeActivationTicket(t, s, ticket)
	if err := s.requireNativeSharing(context.Background(), "sync"); err == nil {
		t.Fatal("same-version receipt bypassed a new transition")
	}
	if err := s.activateSharing(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.requireNativeSharing(context.Background(), "sync"); err != nil {
		t.Fatal(err)
	}
}

func TestSharingAbortUnpackedTransitionRequiresOriginalSourceAndFiles(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "foreign"}[foreign], func(t *testing.T) {
			s, ticket := sharingActivationFixture(t, false)
			if err := s.activateSharing(context.Background()); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
				ticket.Files[path], _ = s.fileSnapshot(path)
			}
			ticket.TargetVersion = "fixture-next"
			ticket.Nonce = nextFixtureNonce
			ticket.Source = sharingActivationSource{Schema: 1, PackageVersion: "fixture-native", PairedRestore: 1, Native: true}
			writeActivationTicket(t, s, ticket)
			if foreign {
				s.write(s.smb, "foreign Samba configuration", 0644)
			}
			err := s.abortSharingActivation(context.Background())
			if (err != nil) != foreign {
				t.Fatal(err)
			}
			if !foreign {
				if err := s.requireNativeSharing(context.Background(), "sync"); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestSharingActivationRejectsUnverifiedTargetBeforeMutation(t *testing.T) {
	s, _ := sharingActivationFixture(t, true)
	s.authorizeTarget = func(context.Context, string) error { return errors.New("fixture missing paired restore contract") }
	if err := s.activateSharing(context.Background()); err == nil {
		t.Fatal("unverified target activated")
	}
	for _, path := range []string{s.state, s.smb, s.exports, s.legacy, s.activationReceipt} {
		if exists, _ := sharingExists(path); exists {
			t.Fatal("unverified target wrote state", path)
		}
	}
	if exists, _ := sharingExists(s.activationTicket); !exists {
		t.Fatal("preflight evidence removed")
	}
}

func TestSharingRestoreGuardAllowsOnlyBoundConversionWitness(t *testing.T) {
	for _, cause := range []string{"matching", "transaction", "phase", "witness", "foreign", "metadata", "unbound"} {
		t.Run(cause, func(t *testing.T) {
			s, _ := sharingActivationFixture(t, false)
			if err := s.activateSharing(context.Background()); err != nil {
				t.Fatal(err)
			}
			files := map[string]sharingFileSnapshot{}
			for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
				files[path], _ = s.fileSnapshot(path)
			}
			guard := sharingGuardMetadata(t, s, map[string]any{"schema": 1, "transaction": "fixture-rollback", "phase": "prepared", "sourceHash": strings.Repeat("a", 64), "witness": files, "source": files})
			t.Setenv("PANASMS_UPDATE_TRANSACTION", "fixture-rollback")
			switch cause {
			case "transaction":
				t.Setenv("PANASMS_UPDATE_TRANSACTION", "other")
			case "phase":
				guard["phase"] = "restoring"
			case "witness":
				guard["witness"] = map[string]sharingFileSnapshot{}
			case "foreign":
				if err := s.write(s.legacy, "foreign grants", 0644); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				var receipt sharingActivationReceipt
				s.metadata(s.activationReceipt, &receipt)
				receipt.Nonce = nextFixtureNonce
				raw, _ := json.Marshal(receipt)
				s.write(s.activationReceipt, string(raw), 0600)
			case "unbound":
				t.Setenv("PANASMS_UPDATE_TRANSACTION", "")
			}
			raw, _ := json.Marshal(guard)
			if err := s.write(s.restoreGuard, string(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if err := s.requireNativeSharing(context.Background(), "sync"); err == nil {
				t.Fatal("guard allowed ordinary mutation")
			}
			err := s.requireNativeSharing(context.Background(), "prepare-downgrade")
			if (err == nil) != (cause == "matching") {
				t.Fatal(cause, err)
			}
		})
	}
}

func TestSharingCommittedActivationRetryNeverReseedsLaterState(t *testing.T) {
	s, ticket := sharingActivationFixture(t, false)
	if err := s.activateSharing(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeActivationTicket(t, s, ticket)
	if err := s.write(s.smb, "later protocol state", 0644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.state)
	if err := s.activateSharing(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(s.state)
	text, _ := sharingText(s.smb)
	if string(before) != string(after) || text != "later protocol state" {
		t.Fatal("committed retry replaced later state")
	}
}

func TestSharingTargetCapabilityMustMatchConfiguredPackage(t *testing.T) {
	for _, raw := range []string{`{"schema":1,"packageVersion":"fixture-native","pairedRestore":1}`, `{"schema":1,"packageVersion":"other","pairedRestore":1}`, `{"schema":2,"packageVersion":"fixture-native","pairedRestore":1}`, `{"schema":1,"packageVersion":"fixture-native","pairedRestore":0}`, `{"schema":1,"packageVersion":"fixture-native","pairedRestore":1,"unverified":true}`} {
		t.Run(raw, func(t *testing.T) {
			s, _ := sharingActivationFixture(t, true)
			s.authorizeTarget = s.requireSharingTarget
			s.run = func(_ context.Context, args []string, _ systemops.CommandOptions) ([]byte, error) {
				if !slices.Equal(args, []string{"/usr/bin/python3", "/usr/lib/panasms/management/sharing_compat.py", "target-capabilities"}) {
					t.Fatal(args)
				}
				return []byte(raw), nil
			}
			err := s.activateSharing(context.Background())
			if (err == nil) != (raw == `{"schema":1,"packageVersion":"fixture-native","pairedRestore":1}`) {
				t.Fatal(err)
			}
		})
	}
}

func TestSharingUncommittedActivationAllowsOnlySourceBoundRollback(t *testing.T) {
	for _, cause := range []string{"baseline", "seeded", "wrong-source", "foreign", "journal", "unguarded", "wrong-guard-source"} {
		t.Run(cause, func(t *testing.T) {
			s, ticket := sharingActivationFixture(t, false)
			if err := s.write(s.lock, "", 0600); err != nil {
				t.Fatal(err)
			}
			if cause == "seeded" {
				real := s.write
				s.write = func(path, value string, mode os.FileMode) error {
					if path == s.activationReceipt {
						return errors.New("receipt fault")
					}
					return real(path, value, mode)
				}
				if err := s.activateSharing(context.Background()); err == nil {
					t.Fatal("receipt fault missed")
				}
				s.write = real
			}
			expected := map[string]sharingFileSnapshot{}
			for path, entry := range ticket.Files {
				expected[path] = entry
			}
			switch cause {
			case "wrong-source":
				entry := expected[s.smb]
				entry.Exists = true
				entry.Mode = 0644
				entry.UID = uint32(s.ownerUID)
				entry.Data = []byte("other backup")
				expected[s.smb] = entry
			case "foreign":
				s.write(s.smb, "foreign policy", 0644)
			case "journal":
				s.write(s.journal, "pending", 0600)
			}
			if err := s.cli(context.Background(), []string{"rollback-check"}, nil, io.Discard); err == nil {
				t.Fatal("unbound pending rollback authorized")
			}
			request, _ := json.Marshal(map[string]any{"schema": 1, "source": expected})
			err := s.cli(context.Background(), []string{"rollback-check", "--source"}, strings.NewReader(string(request)), io.Discard)
			allowed := cause == "baseline" || cause == "seeded" || cause == "unguarded" || cause == "wrong-guard-source"
			if (err == nil) != allowed {
				t.Fatal(cause, err)
			}
			if err := s.requireNativeSharing(context.Background(), "sync"); err == nil {
				t.Fatal("pending rollback enabled ordinary mutation")
			}
			if !allowed {
				return
			}
			witness := map[string]sharingFileSnapshot{}
			for path := range ticket.Files {
				witness[path], _ = s.fileSnapshot(path)
			}
			if cause != "unguarded" {
				source := ticket.Files
				if cause == "wrong-guard-source" {
					source = expected
					entry := source[s.exports]
					entry.Exists = true
					entry.Data = []byte("unrelated backup")
					entry.Mode = 0644
					entry.UID = uint32(s.ownerUID)
					source[s.exports] = entry
				}
				guard, _ := json.Marshal(sharingGuardMetadata(t, s, map[string]any{"schema": 1, "transaction": "pending-rollback", "phase": "prepared", "sourceHash": strings.Repeat("b", 64), "witness": witness, "source": source}))
				s.write(s.restoreGuard, string(guard), 0600)
				t.Setenv("PANASMS_UPDATE_TRANSACTION", "pending-rollback")
			}
			err = s.cli(context.Background(), []string{"prepare-downgrade"}, nil, io.Discard)
			if (err == nil) != (cause == "baseline" || cause == "seeded") {
				t.Fatal("pending prepare", cause, err)
			}
			for path, before := range witness {
				after, _ := s.fileSnapshot(path)
				if !sharingSnapshotsEqual(before, after) {
					t.Fatal("pending prepare rewrote protocol or state", path)
				}
			}
		})
	}
}

func sharingGuardMetadata(t *testing.T, s *sharingService, guard map[string]any) map[string]any {
	t.Helper()
	entries := map[string]sharingFileSnapshot{}
	for _, path := range []string{s.activationReceipt, s.activationTicket} {
		var err error
		entries[path], err = s.fileSnapshot(path)
		if err != nil {
			t.Fatal(err)
		}
	}
	guard["sourceActivation"] = entries
	guard["witnessActivation"] = entries
	return guard
}

func TestSharingActivationRejectsForeignBaselineBeforeSeeding(t *testing.T) {
	s, ticket := sharingActivationFixture(t, false)
	if err := s.write(s.smb, "foreign source policy", 0644); err != nil {
		t.Fatal(err)
	}
	ticket.Files[s.smb], _ = s.fileSnapshot(s.smb)
	writeActivationTicket(t, s, ticket)
	before, _ := os.ReadFile(s.state)
	if err := s.activateSharing(context.Background()); err == nil {
		t.Fatal("foreign baseline activated")
	}
	after, _ := os.ReadFile(s.state)
	if string(before) != string(after) {
		t.Fatal("foreign baseline seeded before rejection")
	}
	if exists, _ := sharingExists(s.activationReceipt); exists {
		t.Fatal("foreign baseline minted receipt")
	}
}

func TestSharingForeignActivationMetadataStopsPackageConversion(t *testing.T) {
	for _, cause := range []string{"receipt-invalid", "ticket-invalid", "receipt-changed", "ticket-changed"} {
		t.Run(cause, func(t *testing.T) {
			s, ticket := sharingActivationFixture(t, false)
			saveSharingFixture(t, s, sharingState{Shares: []sharedFolder{sharingFolder()}, Accounts: map[string]*sharedAccount{}})
			for path := range ticket.Files {
				ticket.Files[path], _ = s.fileSnapshot(path)
			}
			writeActivationTicket(t, s, ticket)
			if err := s.activateSharing(context.Background()); err != nil {
				t.Fatal(err)
			}
			files := map[string]sharingFileSnapshot{}
			for path := range ticket.Files {
				files[path], _ = s.fileSnapshot(path)
			}
			guard := sharingGuardMetadata(t, s, map[string]any{"schema": 1, "transaction": "metadata-cas", "phase": "prepared", "sourceHash": strings.Repeat("c", 64), "witness": files, "source": files})
			switch cause {
			case "receipt-invalid":
				s.write(s.activationReceipt, "{", 0600)
			case "ticket-invalid":
				s.write(s.activationTicket, "{", 0600)
			case "receipt-changed":
				var receipt sharingActivationReceipt
				s.metadata(s.activationReceipt, &receipt)
				receipt.Nonce = nextFixtureNonce
				raw, _ := json.Marshal(receipt)
				s.write(s.activationReceipt, string(raw), 0600)
			case "ticket-changed":
				ticket.Files = files
				writeActivationTicket(t, s, ticket)
			}
			raw, _ := json.Marshal(guard)
			s.write(s.restoreGuard, string(raw), 0600)
			t.Setenv("PANASMS_UPDATE_TRANSACTION", "metadata-cas")
			commands := 0
			s.run = func(context.Context, []string, systemops.CommandOptions) ([]byte, error) { commands++; return nil, nil }
			if err := s.cli(context.Background(), []string{"prepare-downgrade"}, nil, io.Discard); err == nil {
				t.Fatal("foreign metadata authorized conversion", cause)
			}
			for path, before := range files {
				after, _ := s.fileSnapshot(path)
				if !sharingSnapshotsEqual(before, after) {
					t.Fatal("conversion changed policy before metadata rejection", path)
				}
			}
			if commands != 0 {
				t.Fatal("conversion issued commands after foreign metadata", commands)
			}
		})
	}
}

func TestSharingAbortValidatesPreviousTicketSourceBeforeRestoring(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "foreign"}[foreign], func(t *testing.T) {
			s, previous := sharingActivationFixture(t, false)
			if err := s.activateSharing(context.Background()); err != nil {
				t.Fatal(err)
			}
			ticket := previous
			ticket.TargetVersion = "fixture-next"
			ticket.Nonce = nextFixtureNonce
			ticket.Source = sharingActivationSource{Schema: 1, PackageVersion: "fixture-native", PairedRestore: 1, Native: true}
			ticket.Files = map[string]sharingFileSnapshot{}
			for path := range previous.Files {
				ticket.Files[path], _ = s.fileSnapshot(path)
			}
			if foreign {
				previous.Source.Native = true
			}
			ticket.Previous = &previous
			writeActivationTicket(t, s, ticket)
			err := s.abortSharingActivation(context.Background())
			if (err != nil) != foreign {
				t.Fatal(err)
			}
			var actual sharingActivationTicket
			s.metadata(s.activationTicket, &actual)
			if foreign && actual.Nonce != nextFixtureNonce {
				t.Fatal("foreign previous ticket overwrote current evidence")
			}
			if !foreign && (actual.Nonce != fixtureNonce || actual.Source != previous.Source) {
				t.Fatal("previous ticket not restored")
			}
		})
	}
}
