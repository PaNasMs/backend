package api

import (
	"encoding/json"
	"ostojaos.local/backend/internal/store"
	"ostojaos.local/backend/internal/system"
	"testing"
)

func TestCRCAcknowledgementMatchesDiskAndExactCounter(t *testing.T) {
	snapshot := system.Storage{Devices: []map[string]any{{"path": "/dev/sdd", "model": " WDC disk ", "serial": "serial"}}}
	for _, tc := range []struct {
		name, health    string
		warnings        []string
		count, baseline uint64
		wantActive      bool
	}{
		{"accepted", "warning", []string{"UDMA_CRC_Error_Count"}, 7, 7, false},
		{"increased", "warning", []string{"UDMA_CRC_Error_Count"}, 8, 7, true},
		{"decreased", "warning", []string{"UDMA_CRC_Error_Count"}, 6, 7, true},
		{"other fault", "warning", []string{"UDMA_CRC_Error_Count", "Current_Pending_Sector"}, 7, 7, true},
		{"failed health", "failed", []string{"UDMA_CRC_Error_Count"}, 7, 7, true},
		{"unknown warnings", "warning", nil, 7, 7, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disk := smartAlertDisk{Path: "/dev/disk/by-id/ata-test", Device: "/dev/sdd", Health: tc.health, Warnings: tc.warnings}
			json.Unmarshal([]byte(`[{"id":199,"raw":{"value":7}}]`), &disk.Attributes)
			disk.Attributes[0].Raw.Value = &tc.count
			alerts := []store.Alert{{ID: "smart:" + disk.Path, Active: true}, {ID: "heat:" + disk.Path, Active: true}}
			applyCRCAcknowledgements(alerts, map[string]uint64{"WDC disk:serial": tc.baseline}, []smartAlertDisk{disk}, snapshot)
			for _, a := range alerts {
				if a.ID == "smart:"+disk.Path && a.Active != tc.wantActive {
					t.Fatal(a)
				}
				if a.ID == "heat:"+disk.Path && !a.Active {
					t.Fatal("temperature warning hidden")
				}
			}
			alerts = []store.Alert{{ID: "smart:" + disk.Path, Active: true}}
			applyCRCAcknowledgements(alerts, map[string]uint64{"WDC disk:other-serial": tc.baseline}, []smartAlertDisk{disk}, snapshot)
			if !alerts[0].Active {
				t.Fatal("acknowledgement applied to wrong disk")
			}
		})
	}
}
