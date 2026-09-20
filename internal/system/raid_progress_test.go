package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMDProgressSelectsArray(t *testing.T) {
	a := Array{Name: "md127", Sync: "recover"}
	readMDProgress(&a, `md0 : active raid1 sde[0] sdf[1]
 [>....] resync = 55.0% finish=2.0min speed=100K/sec
md127 : active raid5 sdc[3] sdb[1] sda[0]
 1953260544 blocks [3/2] [UU_]
 [>....] recovery = 0.9% (8802280/976630272) finish=143.1min speed=112684K/sec
md1 : active raid1 sdg[0] sdh[1]
 [>....] resync = 80.0% finish=1.0min speed=200K/sec`)
	if a.SyncPercent == nil || *a.SyncPercent != 0.9 || a.SyncSpeed == nil || *a.SyncSpeed != 112684*1024 || a.SyncRemaining == nil || *a.SyncRemaining != 143.1*60 {
		t.Fatalf("wrong progress: %+v", a)
	}
}

func TestMDProgressUnavailableOrIdle(t *testing.T) {
	for _, action := range []string{"idle", "frozen", "recover"} {
		a := Array{Name: "md127", Sync: action}
		source := "md127 : active raid5 sda[0]\n recovery = PENDING"
		if action != "recover" {
			source = "md127 : active raid5 sda[0]\n recovery = 90.0%"
		}
		readMDProgress(&a, source)
		if a.SyncPercent != nil || a.SyncSpeed != nil || a.SyncRemaining != nil {
			t.Fatalf("invented progress: %+v", a)
		}
	}
}

func TestPausedReshapeProgress(t *testing.T) {
	dir := t.TempDir()
	values := map[string]string{"reshape_position": "2277829632", "component_size": "976630272", "raid_disks": "4", "reshape_direction": "forwards"}
	for k, v := range values {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, sync := range []string{"idle", "frozen"} {
		a := Array{Level: "raid5", Sync: sync, State: "read-auto"}
		readMDReshape(&a, dir)
		if !a.ReshapePending || a.SyncPercent == nil || *a.SyncPercent < 38.8 || *a.SyncPercent > 39 {
			t.Fatalf("lost checkpoint: %+v", a)
		}
		if a.SyncSpeed != nil || a.SyncRemaining != nil {
			t.Fatal("paused array has rate or ETA")
		}
	}
	for _, value := range []string{"none", "invalid"} {
		os.WriteFile(filepath.Join(dir, "reshape_position"), []byte(value), 0600)
		a := Array{Level: "raid5", Sync: "idle"}
		readMDReshape(&a, dir)
		if a.ReshapePending || a.SyncPercent != nil {
			t.Fatal("completed array shown as paused")
		}
	}
}
