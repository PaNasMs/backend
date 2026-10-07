package networknative

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
)

type route struct {
	Destination string `json:"dst"`
	Gateway     string `json:"gateway"`
	Device      string `json:"dev"`
	Metric      int    `json:"metric"`
}

func desiredRoutes(source string, rows []map[string]any) []route {
	result := []route{}
	for _, row := range rows {
		if row["dev"] != source {
			continue
		}
		if kind, _ := row["type"].(string); kind != "" && kind != "unicast" {
			continue
		}
		destination, _ := row["dst"].(string)
		if destination == "" {
			destination = "default"
		}
		gateway, _ := row["gateway"].(string)
		metric, _ := row["metric"].(float64)
		result = append(result, route{destination, gateway, source, int(metric)})
	}
	slices.SortFunc(result, func(a, b route) int {
		if (a.Gateway == "") != (b.Gateway == "") {
			if a.Gateway == "" {
				return -1
			}
			return 1
		}
		if a.Destination != b.Destination {
			if a.Destination < b.Destination {
				return -1
			}
			return 1
		}
		return a.Metric - b.Metric
	})
	return result
}

func syncRoutes(g Group, table string, rows []map[string]any) error {
	desired := desiredRoutes(g.Source, rows)
	raw, err := invoke("ip", "-j", "-4", "route", "show", "table", table, "proto", "186")
	if err != nil {
		return err
	}
	var current []map[string]any
	if err = json.Unmarshal(raw, &current); err != nil {
		return err
	}
	if hash(desiredRoutes(g.Source, current)) == hash(desired) && len(current) == len(desired) {
		return nil
	}
	// The unreachable fallback stays installed while the selected uplink changes.
	if err = run("ip", "-4", "route", "flush", "table", table, "proto", "186"); err != nil {
		return err
	}
	for _, r := range desired {
		args := []string{"ip", "-4", "route", "replace", r.Destination}
		if r.Gateway != "" {
			args = append(args, "via", r.Gateway)
		}
		args = append(args, "dev", r.Device, "metric", strconv.Itoa(r.Metric), "proto", "186", "table", table)
		if err = run(args...); err != nil {
			return fmt.Errorf("Selected uplink routing failed: %w", err)
		}
	}
	return nil
}
