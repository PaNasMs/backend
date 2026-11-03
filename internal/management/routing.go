package management

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"panasms.local/backend/internal/modules"
)

// Routing is the single, explicit decision table for where a management
// operation runs. Every management query view and mutation action must appear
// here exactly once. There is deliberately no runtime "try Go, then fall back
// to Python" behavior (plan §3.3): an operation is routed to exactly one
// implementation. Native extensions resolve from the installed registry.
// Python-only extensions retain explicit legacy routing, without retry after
// native failure.
//
// The map value selects exactly one worker. The contract test asserts it stays
// in sync with the OpenAPI ManagementViews and the Python dispatcher.

// impl selects the implementation backing a route.
type impl int

const (
	// legacy routes to the Python management helper over nsenter.
	legacy impl = iota
	// goNative routes to the isolated Go helper after its acceptance checks pass.
	goNative
)

// queryViews lists every management query `view` the panel can request, mapped
// to its implementation. Kept in sync with api/openapi.yaml ManagementViews
// (minus job/jobs, which the Go manager serves directly from its own journal)
// and management/main.py's query dispatch.
var queryViews = map[string]impl{
	"system-updates": legacy,
	"hostname":       goNative,
	"web-access":     goNative,
	// Samba status is obtained through the explicit GO-06 dependency bridge.
	"accounts":          goNative,
	"account-details":   goNative,
	"account-sessions":  goNative,
	"sharing":           goNative,
	"share-folders":     goNative,
	"home-folders":      goNative,
	"data-folders":      goNative,
	"mount-folders":     goNative,
	"network":           goNative,
	"network-access":    goNative,
	"homes-check":       goNative,
	"homes":             goNative,
	"modules":           legacy,
	"module-sources":    legacy,
	"module-catalog":    legacy,
	"storage-options":   goNative,
	"storage-snapshots": legacy,
	"storage-luks":      legacy,
	"raid-candidates":   goNative,
	"smart":             legacy,
	// host.py views: services/journal/power/updates ported to Go in GO-03.
	"services": goNative,
	"journal":  goNative,
	"power":    goNative,
	"updates":  goNative,
	// NFS publication is native; remote filesystem mounts remain owned by GO-07.
	"nfs": goNative,
}

// actionModules mirrors main.py's ACTIONS ownership: each mutation action is
// owned by exactly one module, and every action routes to an implementation.
// Module-contributed (extension) actions are not listed here; they are resolved
// dynamically from installed module registrations.
var actionModules = map[string]impl{
	"storage.recover":             goNative,
	"storage.archive-journal":     goNative,
	"disk.eject":                  legacy,
	"disk.prepare":                legacy,
	"disk.sleep":                  legacy,
	"filesystem.format":           goNative,
	"filesystem.remove":           goNative,
	"filesystem.resize":           goNative,
	"filesystem.snapshot-create":  legacy,
	"filesystem.snapshot-delete":  legacy,
	"filesystem.snapshot-restore": legacy,
	"folder.permissions":          goNative,
	"group.create":                goNative,
	"group.delete":                goNative,
	"group.edit":                  goNative,
	"homes.move":                  goNative,
	"homes.recover":               goNative,
	"luks.close":                  legacy,
	"luks.create":                 legacy,
	"luks.open":                   legacy,
	"luks.key-add":                legacy,
	"luks.key-remove":             legacy,
	"luks.auto-enable":            legacy,
	"luks.auto-disable":           legacy,
	"luks.header-backup":          legacy,
	"luks.header-restore":         legacy,

	"module.catalog-install":    legacy,
	"module.disable":            legacy,
	"module.enable":             legacy,
	"module.install":            legacy,
	"module.recover":            legacy,
	"module.remove":             legacy,
	"module.source-add":         legacy,
	"module.source-remove":      legacy,
	"mount.attach":              legacy,
	"mount.detach":              legacy,
	"mount.open":                legacy,
	"mount.settings":            legacy,
	"network.access.save":       goNative,
	"network.access.stop":       goNative,
	"network.configure":         goNative,
	"network.confirm":           goNative,
	"network.rollback":          goNative,
	"network.share.delete":      goNative,
	"network.share.remove-port": goNative,
	"network.share.save":        goNative,
	"network.share.start":       goNative,
	"network.share.stop":        goNative,
	"network.share.wifi":        goNative,
	"network.wifi.connect":      goNative,
	"network.wifi.disconnect":   goNative,
	"network.wifi.radio":        goNative,
	"network.wifi.scan":         goNative,
	"nfs.export":                goNative,
	"nfs.export-remove":         goNative,
	"nfs.mount":                 goNative,
	"nfs.unmount":               goNative,
	"partition.create":          goNative,
	"partition.delete":          goNative,
	"partition.resize":          goNative,
	"raid.add":                  legacy,
	"raid.check":                legacy,
	"raid.check-stop":           legacy,
	"raid.convert":              legacy,
	"raid.create":               legacy,
	"raid.delete":               legacy,
	"raid.grow":                 legacy,
	"raid.pause":                legacy,
	"raid.replace":              legacy,
	"raid.resume":               legacy,
	"service.disable":           goNative,
	"service.enable":            goNative,
	"service.restart":           goNative,
	"service.start":             goNative,
	"service.stop":              goNative,
	"share.account":             goNative,
	"share.disconnect":          goNative,
	"share.recover":             goNative,
	"share.remove":              goNative,
	"share.save":                goNative,
	"smart.abort":               legacy,
	"smart.long":                legacy,
	"smart.schedule":            legacy,
	"smart.short":               legacy,
	"smart.unschedule":          legacy,
	"smb.mount":                 goNative,
	"smb.unmount":               goNative,
	"system.poweroff":           goNative,
	"system.reboot":             goNative,
	"system.update.check":       legacy,
	"system.update.download":    legacy,
	"system.update.install":     legacy,
	"system.update.rollback":    legacy,
	"system.update.settings":    legacy,
	"system.hostname":           goNative,
	"system.web-port":           goNative,
	"updates.install":           goNative,
	"updates.refresh":           goNative,
	"updates.repair":            goNative,
	"user.create":               goNative,
	"user.delete":               goNative,
	"user.edit":                 goNative,
	"user.home":                 goNative,
	"user.identity":             goNative,
	"user.key.add":              goNative,
	"user.key.delete":           goNative,
	"user.password":             goNative,
	"user.security":             goNative,
	"user.session.end":          goNative,
}

// ErrUnknownView and ErrUnknownAction reject operations with no table entry.
// They match the Python dispatcher's "Administrator permissions required" /
// "Unknown operation" wording only where the panel already relies on it; new
// rejections use explicit, distinct messages.
var (
	ErrUnknownView   = errors.New("Unknown management view")
	ErrUnknownAction = errors.New("Unknown operation")
)

// KnownView reports whether view has a routing entry.
func KnownView(view string) bool { _, ok := queryViews[view]; return ok }

// QueryViews returns the sorted list of every routed query view. The Python
// api_contract test consumes this (via the helper's `routes` subcommand) to
// assert the OpenAPI ManagementViews stay in sync, replacing the former
// AST-walk of main.py.
func QueryViews() []string {
	views := make([]string, 0, len(queryViews))
	for v := range queryViews {
		views = append(views, v)
	}
	sort.Strings(views)
	return views
}

// Inventory is the machine-readable route table emitted for the contract test
// and for audit. goViews/goActions are the subset already migrated to Go.
type Inventory struct {
	Views     []string `json:"views"`
	Actions   []string `json:"actions"`
	GoViews   []string `json:"goViews"`
	GoActions []string `json:"goActions"`
}

// RouteInventory builds the exported inventory from the routing tables.
func RouteInventory() Inventory {
	inv := Inventory{Views: QueryViews(), GoViews: []string{}, GoActions: []string{}}
	for v, dst := range queryViews {
		if dst == goNative {
			inv.GoViews = append(inv.GoViews, v)
		}
	}
	for a, dst := range actionModules {
		inv.Actions = append(inv.Actions, a)
		if dst == goNative {
			inv.GoActions = append(inv.GoActions, a)
		}
	}
	sort.Strings(inv.Actions)
	sort.Strings(inv.GoViews)
	sort.Strings(inv.GoActions)
	return inv
}

// routeQuery returns the implementation for a query view. Enumerated views come
// from the table; other non-empty views may be served by an installed module's
// query extension (main.py load_operations("queries", view), e.g. "files"), so
// they select the native or Python-only dispatcher. Only an empty view is rejected outright here. Ordinary-user access is enforced
// separately in serve.
func routeQuery(view string) (impl, error) {
	if view == "personal-folders" {
		return goNative, nil
	}
	if dst, ok := queryViews[view]; ok {
		return dst, nil
	}
	if view == "" {
		return legacy, ErrUnknownView
	}
	return moduleDestination("queries", view)
}

// runner is the dispatch seam the Manager calls. router wraps a legacy runner
// (the Python helper) and consults the routing table to send Go-routed
// operations to the isolated Go helper instead. Modes plan/execute/recover and
// query all pass through here.
type runner func(context.Context, string, string, any) (json.RawMessage, error)

// goRunner invokes the isolated Go helper. A missing runner is an error,
// never a reason to retry a native operation through Python.
type goRunner func(ctx context.Context, mode, user string, body any) (json.RawMessage, error)

// route wires legacy + Go runners into a single seam honoring the table.
func route(native goRunner, fallback runner) runner {
	return func(ctx context.Context, mode, user string, body any) (json.RawMessage, error) {
		dst, err := destination(mode, body)
		if err != nil {
			return nil, err
		}
		if dst == goNative {
			if native == nil {
				return nil, errors.New("System handler error")
			}
			return native(ctx, mode, user, body)
		}
		return fallback(ctx, mode, user, body)
	}
}

// destination decides the implementation for a request body given its mode.
// Query bodies carry {view,target}; plan/execute/recover carry an action. An
// unroutable request is rejected here, before any subprocess starts.
func destination(mode string, body any) (impl, error) {
	switch mode {
	case "query":
		view := bodyString(body, "view")
		return routeQuery(view)
	case "plan", "execute", "recover":
		action := bodyString(body, "action")
		if mode == "recover" && action == "module.catalog-install" {
			return goNative, nil
		}
		if dst, ok := actionModules[action]; ok {
			return dst, nil
		}
		if mode == "recover" {
			return goNative, nil
		}
		return moduleDestination("actions", action)

	}
	return legacy, errors.New("Unknown operation mode")
}

// bodyString extracts a string field from either a Request or a map body.
func bodyString(body any, field string) string {
	switch v := body.(type) {
	case Request:
		if field == "action" {
			return v.Action
		}
	case map[string]any:
		if s, ok := v[field].(string); ok {
			return s
		}
	case map[string]string:
		return v[field]
	}
	return ""
}

func reservedModuleRoute(kind, name string) bool {
	if kind == "actions" {
		_, ok := actionModules[name]
		return ok
	}
	_, ok := queryViews[name]
	return ok || name == "personal-folders" || name == "job" || name == "jobs"
}

func moduleDestination(kind, name string) (impl, error) {
	m, err := modules.Operation(kind, name, reservedModuleRoute)
	if err != nil {
		return legacy, err
	}
	if m != nil && m.ID != "files" && kind == "actions" && memberModuleActions[name] {
		return legacy, errors.New("Module registration uses reserved Files actions")
	}
	if m != nil && m.Operations != "" {
		return goNative, nil
	}
	return legacy, nil
}
