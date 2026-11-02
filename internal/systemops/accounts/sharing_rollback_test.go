package accounts

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"panasms.local/backend/internal/systemops"
)

func sharingRollbackFixture(t *testing.T, shares []sharedFolder) *sharingService {
	t.Helper()
	s := sharingFixture(t)
	saveSharingFixture(t, s, sharingState{Shares: shares, Accounts: map[string]*sharedAccount{}})
	sealLegacySharingFixture(t, s)
	if err := s.write(s.lock, "", 0600); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSharingRollbackWitnessIsReadOnlyAndPreservesExactAbsence(t *testing.T) {
	s := sharingRollbackFixture(t, []sharedFolder{})
	os.Remove(s.exports)
	before, _ := os.ReadFile(s.state)
	var out strings.Builder
	if err := s.cli(context.Background(), []string{"rollback-check"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	var witness struct {
		Schema int
		Files  map[string]map[string]any
	}
	if err := json.Unmarshal([]byte(out.String()), &witness); err != nil {
		t.Fatal(err)
	}
	if witness.Schema != 1 || len(witness.Files) != 4 || !reflect.DeepEqual(witness.Files[s.legacy], map[string]any{"exists": false}) || !reflect.DeepEqual(witness.Files[s.exports], map[string]any{"exists": false}) {
		t.Fatal(witness)
	}
	after, _ := os.ReadFile(s.state)
	if string(before) != string(after) {
		t.Fatal("read-only witness changed sharing state")
	}
	if exists, _ := sharingExists(s.journal); exists {
		t.Fatal("read-only witness created a journal")
	}
}

func TestSharingRollbackWitnessRefusesForeignFilesAndPendingJournal(t *testing.T) {
	for _, cause := range []string{"smb", "legacy", "mode", "journal", "link", "hardlink"} {
		t.Run(cause, func(t *testing.T) {
			s := sharingRollbackFixture(t, []sharedFolder{sharingFolder()})
			switch cause {
			case "smb":
				s.write(s.smb, "foreign edit", 0644)
			case "legacy":
				s.write(s.legacy, "foreign NFS grants", 0644)
			case "mode":
				s.write(s.legacy, "", 0600)
			case "journal":
				s.write(s.journal, "pending", 0600)
			case "link":
				os.Rename(s.smb, s.smb+"-saved")
				os.Symlink(s.smb+"-saved", s.smb)
			case "hardlink":
				os.Link(s.smb, s.smb+"-link")
			}
			before, _ := sharingText(s.smb)
			if _, err := s.rollbackWitness(context.Background()); err == nil {
				t.Fatal("foreign or pending state accepted")
			}
			after, _ := sharingText(s.smb)
			if before != after {
				t.Fatal("refused witness changed configuration")
			}
		})
	}
}

func TestSharingPackageConversionAndMigrationNeverStartInactiveServers(t *testing.T) {
	s := sharingRollbackFixture(t, []sharedFolder{sharingFolder()})
	commands := [][]string{}
	real := s.run
	s.run = func(ctx context.Context, args []string, opt systemops.CommandOptions) ([]byte, error) {
		commands = append(commands, slices.Clone(args))
		if len(args) > 1 && args[0] == "systemctl" && args[1] == "is-active" {
			return []byte("inactive"), nil
		}
		return real(ctx, args, opt)
	}
	if err := s.cli(context.Background(), []string{"prepare-downgrade"}, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := s.republish(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, args := range commands {
		if slices.Contains(args, "enable") || slices.Contains(args, "start") || args[0] == "exportfs" || args[0] == "smbcontrol" {
			t.Fatal("package conversion activated or reloaded inactive server", args)
		}
	}
}

func TestSharingRollbackRefusesAccountChangesWithoutPassdbSnapshot(t *testing.T) {
	for _, field := range []string{"enabled", "uid", "status", "passwordRevision", "unknown"} {
		t.Run(field, func(t *testing.T) {
			s := sharingRollbackFixture(t, []sharedFolder{})
			st, _ := s.read()
			uid := 1000
			st.Accounts["alice"] = &sharedAccount{UID: &uid, Enabled: true, Status: "synced", PasswordRevision: "current"}
			saveSharingFixture(t, s, st)
			source := map[string]sharingFileSnapshot{}
			for _, path := range []string{s.state, s.smb, s.exports, s.legacy} {
				source[path], _ = s.fileSnapshot(path)
			}
			var raw map[string]any
			json.Unmarshal(source[s.state].Data, &raw)
			old := raw["accounts"].(map[string]any)["alice"].(map[string]any)
			switch field {
			case "enabled":
				old[field] = false
			case "uid":
				old[field] = 1001
			case "status":
				old[field] = "pending"
			case "passwordRevision":
				old[field] = "old"
			case "unknown":
				old[field] = "preserve unknown policy"
			}
			entry := source[s.state]
			entry.Data, _ = json.Marshal(raw)
			source[s.state] = entry
			request, _ := json.Marshal(map[string]any{"schema": 1, "source": source})
			if err := s.cli(context.Background(), []string{"rollback-check", "--source"}, strings.NewReader(string(request)), io.Discard); err == nil {
				t.Fatal("account difference accepted", field)
			}
			if pending, _ := sharingExists(s.journal); pending {
				t.Fatal("read-only rollback check created journal")
			}
		})
	}
}
