package localmounts

import (
	"context"
	"panasms.local/backend/internal/systemops/storagebase"
	"testing"
)

func TestPendingMountConfigRetryAlwaysReloadsWithoutAdoptingForeignEdit(t *testing.T) {
	prior := testJournal()
	prior.Action = "mount.attach"
	prior.FstabBefore = storagebase.Hash("before")
	prior.FstabDesired = "desired"
	for _, current := range []string{"before", "desired"} {
		reload, err := pendingConfiguration(prior, current)
		if err != nil || !reload {
			t.Fatalf("current %q: reload=%v err=%v", current, reload, err)
		}
	}
	if _, err := pendingConfiguration(prior, "foreign"); err == nil {
		t.Fatal("foreign fstab adopted")
	}
	prior.ConfigReconciled = true
	prior.ConfigResolution = "desired"
	prior.ConfigWitness = storagebase.Hash("desired")
	if reload, err := pendingConfiguration(prior, "desired"); err != nil || reload {
		t.Fatal(reload, err)
	}
	if _, err := pendingConfiguration(prior, "foreign"); err == nil {
		t.Fatal("old acknowledgement accepted foreign edit")
	}
}
func TestPendingDiskPreparationRequiresBoundedConfigRecovery(t *testing.T) {
	prior := testJournal()
	prior.FstabBefore = storagebase.Hash("before")
	prior.FstabDesired = "desired"
	if _, err := pendingConfiguration(prior, "before"); err == nil {
		t.Fatal("destructive journal superseded without reconciliation")
	}
	prior.ConfigReconciled = true
	prior.ConfigResolution = "before"
	prior.ConfigWitness = storagebase.Hash("before")
	if reload, err := pendingConfiguration(prior, "before"); err != nil || reload {
		t.Fatal(reload, err)
	}
	prior.ConfigResolution = "unknown"
	if _, err := pendingConfiguration(prior, "before"); err == nil {
		t.Fatal("unknown resolution accepted")
	}
}

func TestForeignMountConfigurationBlocksReassignmentButAllowsOfflineRepair(t *testing.T) {
	s := fixtureService(t)
	s.fstab = func() (string, error) { return "UUID=test-uuid /srv/custom ext4 ro,nodev 0 2\n", nil }
	params := map[string]any{"target": "/dev/sda", "point": "/mnt/planned"}
	for _, action := range []string{"mount.attach", "mount.settings", "mount.open"} {
		if _, err := s.prepare(context.Background(), action, params, "admin"); err == nil {
			t.Fatal(action + " accepted foreign configuration")
		}
	}
	params["mode"] = "repair-only"
	if _, err := s.prepare(context.Background(), "mount.open", params, "admin"); err != nil {
		t.Fatal(err)
	}
}
