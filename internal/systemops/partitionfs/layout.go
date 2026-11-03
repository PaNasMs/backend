package partitionfs

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagequery"
)

type runner func(context.Context, []string, systemops.CommandOptions) ([]byte, error)
type service struct {
	revalidate  func(context.Context, string, *transaction) error
	writeConfig func(context.Context, string, string, *systemops.Reporter) error
	root        string
	owner       int
	write       func(string, string, os.FileMode) error
	sys         string
	run         runner
	identity    func(*storagequery.Preflight, string) (storagequery.StorageIdentity, error)
	config      func() (string, error)
	find        func(string) (string, error)
}

func reject(message string) error                { return &systemops.Rejected{Message: message} }
func text(row map[string]any, key string) string { s, _ := row[key].(string); return s }
func number(value any) (uint64, error) {
	switch n := value.(type) {
	case json.Number:
		return strconv.ParseUint(string(n), 10, 64)
	case uint64:
		return n, nil
	case float64:
		if n >= 0 && n < 18446744073709551616.0 && !math.IsNaN(n) && math.Trunc(n) == n {
			return uint64(n), nil
		}
	}
	return 0, reject("Invalid storage geometry")
}
func (s *service) sectorValue(name, field string) (uint64, error) {
	if filepath.Base(name) != name || name == "." || name == ".." {
		return 0, reject("Invalid storage geometry")
	}
	b, err := os.ReadFile(filepath.Join(s.sys, name, field))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n > math.MaxUint64/512 {
		return 0, reject("Invalid storage geometry")
	}
	return n * 512, nil
}
func (s *service) jsonCommand(ctx context.Context, args []string) (map[string]any, error) {
	data, err := s.run(ctx, args, systemops.CommandOptions{})
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err = systemops.Decode(data, &result); err != nil || result == nil {
		return nil, reject("Could not read the partition table. No changes were made.")
	}
	return result, nil
}
func tableParts(table map[string]any) ([]map[string]any, error) {
	values, ok := table["partitions"].([]any)
	if table["partitions"] == nil {
		return []map[string]any{}, nil
	}
	if !ok {
		return nil, reject("Invalid storage geometry")
	}
	result := []map[string]any{}
	for _, v := range values {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, reject("Invalid storage geometry")
		}
		result = append(result, row)
	}
	return result, nil
}
func sectorSize(table map[string]any) (uint64, error) {
	if table["sectorsize"] == nil {
		return 512, nil
	}
	n, err := number(table["sectorsize"])
	if err != nil || n < 512 || n > 65536 || n&(n-1) != 0 {
		return 0, reject("Invalid storage geometry")
	}
	return n, nil
}
func (s *service) table(ctx context.Context, target string) (map[string]any, error) {
	data, err := s.jsonCommand(ctx, []string{"sfdisk", "--json", target})
	if err != nil {
		return nil, err
	}
	table, ok := data["partitiontable"].(map[string]any)
	if !ok || (text(table, "label") != "gpt" && text(table, "label") != "dos") {
		return nil, reject("Unsupported partition table. No changes were made.")
	}
	return table, nil
}
func (s *service) checkedLayout(ctx context.Context, target string, p *storagequery.Preflight) (map[string]any, error) {
	if err := p.Layout(target); err != nil {
		return nil, err
	}
	probe, err := s.jsonCommand(ctx, []string{"wipefs", "--json", "--no-act", "--output", "TYPE,OFFSET", "--", target})
	if err != nil {
		return nil, err
	}
	sigs, ok := probe["signatures"].([]any)
	if !ok {
		return nil, reject("Could not read the partition table. No changes were made.")
	}
	if len(sigs) == 0 {
		if len(p.Inventory.Descendants(target)) != 1 {
			return nil, reject("Partition metadata is inconsistent. No changes were made.")
		}
		return nil, nil
	}
	overlapping, atari := false, false
	for _, v := range sigs {
		sig, ok := v.(map[string]any)
		if !ok {
			return nil, reject("Could not read the partition table. No changes were made.")
		}
		overlapping = overlapping || text(sig, "type") == "dos" && text(sig, "offset") == "0x1fe"
	}
	for _, v := range sigs {
		sig := v.(map[string]any)
		kind := text(sig, "type")
		switch kind {
		case "gpt", "PMBR", "dos":
		case "atari":
			if !overlapping || text(sig, "offset") != "0x1d2" {
				return nil, reject("Existing signatures prevent creating a partition. Prepare the disk explicitly first.")
			}
			atari = true
		default:
			return nil, reject("Existing signatures prevent creating a partition. Prepare the disk explicitly first.")
		}
	}
	table, err := s.table(ctx, target)
	if err != nil {
		return nil, err
	}
	parts, err := tableParts(table)
	if err != nil {
		return nil, err
	}
	if atari && (text(table, "label") != "dos" || len(parts) == 0 || len(p.Inventory.Descendants(target)) == 1) {
		return nil, reject("Existing signatures prevent creating a partition. Prepare the disk explicitly first.")
	}
	sector, err := sectorSize(table)
	if err != nil {
		return nil, err
	}
	direct := map[string]bool{}
	for path, parents := range p.Inventory.Parents {
		if parents[target] && text(p.Inventory.Rows[path], "type") == "part" {
			direct[path] = true
		}
	}
	if len(direct) != len(parts) {
		return nil, reject("Partition metadata is inconsistent. No changes were made.")
	}
	seen := map[string]bool{}
	for _, part := range parts {
		kind := strings.ToLower(text(part, "type"))
		if kind == "5" || kind == "f" || kind == "85" || kind == "05" || kind == "0f" {
			return nil, reject("Unsupported partition table. No changes were made.")
		}
		path := text(part, "node")
		if !direct[path] || seen[path] {
			return nil, reject("Partition metadata is inconsistent. No changes were made.")
		}
		seen[path] = true
		row := p.Inventory.Rows[path]
		start, err := s.sectorValue(text(row, "kname"), "start")
		if err != nil {
			return nil, err
		}
		size, err := number(row["size"])
		if err != nil {
			return nil, err
		}
		a, ea := number(part["start"])
		b, eb := number(part["size"])
		if ea != nil || eb != nil || a > math.MaxUint64/sector || b > math.MaxUint64/sector || start != a*sector || size != b*sector {
			return nil, reject("Partition metadata is inconsistent. No changes were made.")
		}
	}
	return table, nil
}
func (s *service) verifyKernel(part map[string]any, sector uint64) error {
	path := text(part, "node")
	if filepath.Dir(path) != "/dev" {
		return reject("Invalid storage geometry")
	}
	for _, field := range []string{"start", "size"} {
		actual, err := s.sectorValue(filepath.Base(path), field)
		value, e := number(part[field])
		if err != nil || e != nil || sector == 0 || value > math.MaxUint64/sector || actual != value*sector {
			return reject("The partition table changed, but the kernel has not confirmed it. Restart the NAS before retrying.")
		}
	}
	return nil
}
func integer(params map[string]any, key string, min, max uint64) (uint64, error) {
	n, err := number(params[key])
	if err != nil || n < min || n > max {
		return 0, reject(fmt.Sprintf("%s must be between %d and %d", key, min, max))
	}
	return n, nil
}
