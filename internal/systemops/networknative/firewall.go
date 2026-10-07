package networknative

import (
	"encoding/json"
	"fmt"
	"os"
)

func ensureNAT(g Group) error {
	name := "panasms_" + g.ID
	if raw, err := invoke("nft", "-j", "list", "table", "ip", name); err == nil {
		var document struct {
			NFTables []struct {
				Table *struct {
					Comment string `json:"comment"`
				} `json:"table"`
			} `json:"nftables"`
		}
		if err = json.Unmarshal(raw, &document); err != nil {
			return err
		}
		for _, item := range document.NFTables {
			if item.Table != nil && item.Table.Comment == "PaNasMs native sharing" {
				return nil
			}
		}
		return fmt.Errorf("A firewall table conflicts with connection sharing")
	}
	file, err := os.CreateTemp("/run", "panasms-nat-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	contents := fmt.Sprintf("table ip %s {\n comment \"PaNasMs native sharing\"\n chain postrouting {\n type nat hook postrouting priority srcnat; policy accept;\n ip saddr %s oifname %q masquerade\n }\n}\n", name, g.Subnet, g.Source)
	if _, err = file.WriteString(contents); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return run("nft", "-f", file.Name())
}
