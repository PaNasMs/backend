package network

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestLiveNativeInventory(t *testing.T) {
	if os.Getenv("PANASMS_NATIVE_TEST_QUERY") != "1" {
		t.Skip("requires an authorized native network test host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if a, err := connect(); err == nil {
		a.bus.Close()
		t.Fatal("NetworkManager must be stopped")
	}
	raw, err := Query(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	rows, ok := result["interfaces"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatal("interface inventory missing")
	}
	for _, row := range rows {
		value := row.(map[string]any)
		t.Logf("interface=%v kind=%v manager=%v source=%v", value["name"], value["kind"], value["manager"], value["configurationSource"])
	}
}
