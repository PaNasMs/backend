package accounts

import (
	"context"
	"net/netip"
	"os"
	"strings"

	"panasms.local/backend/internal/systemops"
)

func sharingNetwork(value string) (string, error) {
	prefix, err := netip.ParsePrefix(value)
	if err == nil {
		return prefix.Masked().String(), nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return "", reject("Specify NFS clients as IP addresses or subnets")
	}
	return netip.PrefixFrom(address, address.BitLen()).String(), nil
}

type legacyExport struct {
	Path     string   `json:"path"`
	Clients  []string `json:"clients"`
	ReadOnly bool     `json:"readOnly"`
}

func (s *sharingService) nfsEntries() ([]legacyExport, error) {
	text, err := sharingText(s.legacy)
	if err != nil {
		return nil, err
	}
	rows := []legacyExport{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		row := legacyExport{Path: fields[0], Clients: []string{}, ReadOnly: true}
		for _, value := range fields[1:] {
			row.Clients = append(row.Clients, strings.SplitN(value, "(", 2)[0])
			row.ReadOnly = row.ReadOnly && strings.Contains(value, "(ro,")
		}
		rows = append(rows, row)
	}
	return rows, nil
}
func (s *sharingService) nfsQuery() ([]byte, error) {
	rows, err := s.nfsEntries()
	if err != nil {
		return nil, err
	}
	return marshal(map[string]any{"exports": rows})
}
func (s *sharingService) nfsPlan(ctx context.Context, action string, p map[string]any) ([]byte, error) {
	target := stringParam(p, "target")
	mount, err := s.locate(ctx, target)
	if err != nil {
		return nil, err
	}
	text, err := sharingText(s.legacy)
	if err != nil {
		return nil, err
	}
	clients := stringParam(p, "clients")
	if action == "nfs.export" {
		if value, present := p["readOnly"]; present {
			if _, ok := value.(bool); !ok {
				return nil, reject("Protocol settings must be true or false")
			}
		}
		values := strings.Split(clients, ",")
		if len(values) == 0 || len(values) > 32 {
			return nil, reject("Specify NFS clients")
		}
		for _, value := range values {
			if _, err = sharingNetwork(strings.TrimSpace(value)); err != nil {
				return nil, reject("Specify clients as comma-separated IP addresses or subnets")
			}
		}
	}
	id, err := s.identity(target)
	if err != nil {
		return nil, err
	}
	fp, err := fingerprint(action, p, []any{text, mount, id})
	if err != nil {
		return nil, err
	}
	return marshal(map[string]any{"target": target, "confirmation": target, "details": []string{target, "Clients: " + clients, "NFS: Linux UID/GID permissions; root_squash enabled"}, "fingerprint": fp})
}
func (s *sharingService) nfsExecute(ctx context.Context, action string, p map[string]any, r *systemops.Reporter) ([]byte, error) {
	target := stringParam(p, "target")
	mount, err := s.locate(ctx, target)
	if err != nil {
		return nil, err
	}
	text, err := sharingText(s.legacy)
	if err != nil {
		return nil, err
	}
	rows := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, target+" ") {
			rows = append(rows, line)
		}
	}
	if action == "nfs.export" {
		clients := []string{}
		mode := "rw"
		if enabled, _ := p["readOnly"].(bool); enabled {
			mode = "ro"
		}
		for _, client := range strings.Split(stringParam(p, "clients"), ",") {
			clients = append(clients, strings.TrimSpace(client)+"("+mode+",sync,no_subtree_check,root_squash,mountpoint="+mount.Target+")")
		}
		rows = append(rows, target+" "+strings.Join(clients, " "))
	}
	if err = s.begin(true); err != nil {
		return nil, err
	}
	if err = s.write(s.legacy, strings.Join(rows, "\n")+"\n", os.FileMode(0644)); err != nil {
		return nil, s.rollback(ctx, r)
	}
	if _, err = s.command(ctx, []string{"systemctl", "enable", "--now", "nfs-kernel-server"}, true, r); err != nil {
		return nil, s.rollback(ctx, r)
	}
	if err = s.validateLegacy(ctx); err != nil {
		return nil, s.rollback(ctx, r)
	}
	if _, err = s.command(ctx, []string{"exportfs", "-ra"}, true, r); err != nil {
		return nil, s.rollback(ctx, r)
	}
	if err = removeSharingFile(s.journal); err != nil {
		return nil, err
	}
	return marshal(map[string]string{"message": "NFS share updated"})
}

func (s *sharingService) validateLegacy(ctx context.Context) error {
	rows, err := s.nfsEntries()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if _, err = s.locate(ctx, row.Path); err != nil {
			return reject("Shared volume unavailable")
		}
	}
	return nil
}
