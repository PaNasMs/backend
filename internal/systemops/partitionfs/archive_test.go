package partitionfs

import (
	"encoding/json"
	"os"
	"panasms.local/backend/internal/systemops/storagequery"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestArchiveReviewTracksEvidenceAndPreservesExactOriginal(t *testing.T) {
	s, p := planningFixture(t)
	const device = "/dev/sda1"
	id, err := s.identity(p, device)
	if err != nil {
		t.Fatal(err)
	}
	initial := transaction{Schema: 1, Domain: "partitionfs", Phase: "pending", Action: "partition.delete", Target: device, Fingerprint: strings.Repeat("0", 64), Identity: id, Steps: []step{{"delete-partition", true}}, FstabBefore: journalKey("before"), FstabDesired: "after"}
	data, _ := json.Marshal(initial)
	data = append([]byte(" \n"), data...)
	data = append(data, '\n')
	if err = os.WriteFile(s.journalPath(device), data, 0600); err != nil {
		t.Fatal(err)
	}
	state, h, err := s.loadWithDigest(device)
	if err != nil {
		t.Fatal(err)
	}
	current := "after\n# unrelated mount"
	s.config = func() (string, error) { return current, nil }
	delete(p.Inventory.Rows, device)
	first, err := s.archiveReview(state, h, current, "new-boot", p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(first.details, " "), "recorded device is absent") {
		t.Fatal(first.details)
	}
	for _, tc := range []struct{ config, boot, digest string }{{current + "\n", "new-boot", h}, {current, "another-boot", h}, {current, "new-boot", journalKey("other bytes")}} {
		other, err := s.archiveReview(state, tc.digest, tc.config, tc.boot, p)
		if err != nil || other.fingerprint == first.fingerprint {
			t.Fatalf("stale evidence not detected: %v", err)
		}
	}
	p.Inventory.Rows[device] = map[string]any{"path": device, "type": "part", "uuid": "replacement"}
	s.identity = func(_ *storagequery.Preflight, _ string) (storagequery.StorageIdentity, error) {
		i := id
		i.BootID = "new-boot"
		return i, nil
	}
	replaced, err := s.archiveReview(state, h, current, "new-boot", p)
	if err != nil || replaced.fingerprint == first.fingerprint {
		t.Fatalf("changed device ignored: %v", err)
	}
	delete(p.Inventory.Rows, device)
	current += "\n# late change"
	if err = s.archiveOriginal(first); err == nil {
		t.Fatal("late configuration edit ignored")
	}
	current = strings.TrimSuffix(current, "\n# late change")
	if err = os.WriteFile(s.journalPath(device), append(append([]byte{}, data...), ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.archiveOriginal(first); err == nil {
		t.Fatal("late journal edit ignored")
	}
	if err = os.WriteFile(s.journalPath(device), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.archiveOriginal(first); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(s.journalPath(device)); !os.IsNotExist(err) {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(s.root, "*.history-ack-*"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("%v %v", paths, err)
	}
	saved, err := os.ReadFile(paths[0])
	if err != nil || !reflect.DeepEqual(saved, data) {
		t.Fatal("original bytes changed")
	}
	if err = s.archiveOriginal(first); err == nil {
		t.Fatal("acknowledgement replayed")
	}
}

func TestArchiveIsUnavailableForOrdinaryPendingRecord(t *testing.T) {
	s, p := planningFixture(t)
	target := "/dev/sda1"
	id, err := s.identity(p, target)
	if err != nil {
		t.Fatal(err)
	}
	current := "# original configuration\n"
	state := &transaction{Action: "partition.create", Target: target, Identity: id, Phase: "pending", FstabBefore: journalKey(current), FstabDesired: current}
	for _, conf := range []string{current, current + "# unrelated row\n"} {
		if _, err = s.archiveReview(state, journalKey("record"), conf, id.BootID, p); err == nil {
			t.Fatal("ordinary pending record became archivable")
		}
	}
}

func TestValidConfigurationAcknowledgementDoesNotLoopAfterDisappearingTarget(t *testing.T) {
	s, p := planningFixture(t)
	target := "/dev/sda1"
	id, err := s.identity(p, target)
	if err != nil {
		t.Fatal(err)
	}
	state := &transaction{Action: "partition.delete", Target: target, Identity: id, Phase: "pending", FstabBefore: journalKey("before"), FstabDesired: "after", Steps: []step{{"delete-partition", true}, {"future-inspection", true}}}
	state.ConfigOnlyRemaining = true
	state.ConfigReconciled = true
	state.ConfigResolution = "desired"
	state.ConfigWitness = journalKey("after")
	delete(p.Inventory.Rows, target)
	if state.needsConfigRecovery("after") {
		t.Fatal("already acknowledged bytes incorrectly routed back to recovery")
	}
	if _, err = s.archiveReview(state, journalKey("raw evidence"), "after", id.BootID, p); err != nil {
		t.Fatal(err)
	}
	if !state.needsConfigRecovery("before") {
		t.Fatal("changed acknowledgement bypassed ordinary configuration recovery")
	}
}
