package localmounts

import (
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
