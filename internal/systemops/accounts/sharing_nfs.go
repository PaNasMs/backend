package accounts

import (
	"context"
	"net/netip"
	"os"
	"slices"
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
func (s *sharingService) nfsPlan(ctx context.Context, action string, p map[string]any, st sharingState) ([]byte, error) {
	target := stringParam(p, "target")
	if err := sharePathShape(target); err != nil {
		return nil, err
	}
	text, err := sharingText(s.legacy)
	if err != nil {
		return nil, err
	}
	clients := stringParam(p, "clients")
	state := []any{text}
	if action == "nfs.export-remove" {
		rows, err := s.nfsEntries()
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(rows, func(row legacyExport) bool { return row.Path == target }) {
			return nil, reject("NFS publication no longer exists")
		}
	} else {
		if slices.ContainsFunc(st.Shares, func(share sharedFolder) bool { return share.NFS && share.Path == target }) {
			return nil, reject("This folder is already managed by Shared folders")
		}
		mount, err := s.locate(ctx, target)
		if err != nil {
			return nil, err
		}
		id, err := s.identity(target)
		if err != nil {
			return nil, err
		}
		state = append(state, mount, id)
		if value, present := p["readOnly"]; present {
			if _, ok := value.(bool); !ok {
				return nil, reject("Protocol settings must be true or false")
			}
		}
		values := strings.Split(clients, ",")
		if len(values) > 32 {
			return nil, reject("Specify NFS clients")
		}
		for _, value := range values {
			if _, err = sharingNetwork(strings.TrimSpace(value)); err != nil {
				return nil, reject("Specify clients as comma-separated IP addresses or subnets")
			}
		}
	}
	fp, err := fingerprint(action, p, state)
	if err != nil {
		return nil, err
	}
	return marshal(map[string]any{"target": target, "confirmation": target, "details": []string{target, "Clients: " + clients, "NFS: Linux UID/GID permissions; root_squash enabled"}, "fingerprint": fp})
}

func (s *sharingService) nfsExecute(ctx context.Context, action string, p map[string]any, r *systemops.Reporter) ([]byte, error) {
	target := stringParam(p, "target")
	var mount sharingMount
	var err error
	if action == "nfs.export" {
		mount, err = s.locate(ctx, target)
		if err != nil {
			return nil, err
		}
	}
	reload := true
	if action == "nfs.export-remove" {
		raw, err := s.run(ctx, []string{"systemctl", "is-active", "nfs-kernel-server"}, systemops.CommandOptions{Accepted: []int{0, 3, 4}})
		if err != nil {
			return nil, systemops.BeforeMutation(err)
		}
		reload = strings.TrimSpace(string(raw)) == "active"
		previous := s.preserveServiceState
		s.preserveServiceState = true
		defer func() { s.preserveServiceState = previous }()
	}
	text, err := sharingText(s.legacy)
	if err != nil {
		return nil, err
	}
	rows := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		fields := strings.Fields(line)
		if line != "" && (len(fields) == 0 || fields[0] != target) {
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
	st, err := s.read()
	if err != nil {
		return nil, err
	}
	if err = s.validate(ctx, st.Shares, r); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if err = s.validateLegacyRevision(st); err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	if err = s.begin(true); err != nil {
		return nil, err
	}
	if err = s.write(s.legacy, strings.Join(rows, "\n")+"\n", os.FileMode(0644)); err != nil {
		return nil, s.rollback(ctx, r)
	}
	if action == "nfs.export" {
		if _, err = s.command(ctx, []string{"systemctl", "enable", "--now", "nfs-kernel-server"}, true, r); err != nil {
			return nil, s.rollback(ctx, r)
		}
	}
	if reload {
		if _, err = s.command(ctx, []string{"exportfs", "-ra"}, true, r); err != nil {
			return nil, s.rollback(ctx, r)
		}
	}
	st.LegacyExportRevision, err = s.legacyRevision()
	if err != nil {
		return nil, s.rollback(ctx, r)
	}
	if err = s.save(st); err != nil {
		return nil, s.rollback(ctx, r)
	}
	if err = removeSharingFile(s.journal); err != nil {
		return nil, err
	}
	return marshal(map[string]string{"message": "NFS share updated"})
}
