package management

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
)

// Routing is the single, explicit decision table for where a management
// operation runs. Every management query view and mutation action must appear
// here exactly once. There is deliberately no runtime "try Go, then fall back
// to Python" behavior (plan §3.3): an operation is routed to exactly one
// implementation. Unknown non-empty views/actions go to the legacy dispatcher
// for module-extension lookup and authorization, never to a shell RPC.
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
	"web-access":     goNative,
	// Samba status is obtained through the explicit GO-06 dependency bridge.
	"accounts":         goNative,
	"account-details":  goNative,
	"account-sessions": goNative,
	"sharing":          legacy,
	"share-folders":    legacy,
	"home-folders":     legacy,
	"mount-folders":    legacy,
	"network":          legacy,
	"homes-check":      legacy,
	"homes":            legacy,
	"modules":          legacy,
	"module-sources":   legacy,
	"module-catalog":   legacy,
	"storage-options":  legacy,
	"raid-candidates":  legacy,
	"smart":            legacy,
	// host.py views: services/journal/power/updates ported to Go in GO-03.
	"services": goNative,
	"journal":  goNative,
	"power":    goNative,
	"updates":  goNative,
	// nfs export listing stays legacy until GO-07 owns sharing/mounts.
	"nfs": legacy,
}

// actionModules mirrors main.py's ACTIONS ownership: each mutation action is
// owned by exactly one module, and every action routes to an implementation.
// Module-contributed (extension) actions are not listed here; they are resolved
// dynamically and always run legacy until GO-12/GO-14 move the module protocol.
var actionModules = map[string]impl{
	"disk.eject":                legacy,
	"disk.prepare":              legacy,
	"disk.sleep":                legacy,
	"filesystem.format":         legacy,
	"filesystem.resize":         legacy,
	"folder.permissions":        legacy,
	"group.create":              goNative,
	"group.delete":              goNative,
	"group.edit":                goNative,
	"homes.move":                legacy,
	"homes.recover":             legacy,
	"luks.close":                legacy,
	"luks.create":               legacy,
	"luks.open":                 legacy,
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
	"network.configure":         legacy,
	"network.confirm":           legacy,
	"network.rollback":          legacy,
	"network.share.delete":      legacy,
	"network.share.remove-port": legacy,
	"network.share.save":        legacy,
	"network.share.start":       legacy,
	"network.share.stop":        legacy,
	"network.share.wifi":        legacy,
	"network.wifi.connect":      legacy,
	"network.wifi.disconnect":   legacy,
	"network.wifi.radio":        legacy,
	"network.wifi.scan":         legacy,
	"nfs.export":                legacy,
	"nfs.export-remove":         legacy,
	"nfs.mount":                 legacy,
	"nfs.unmount":               legacy,
	"partition.create":          legacy,
	"partition.delete":          legacy,
	"partition.resize":          legacy,
	"raid.add":                  legacy,
	"raid.check":                legacy,
	"raid.check-stop":           legacy,
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
	"share.account":             legacy,
	"share.disconnect":          legacy,
	"share.recover":             legacy,
	"share.remove":              legacy,
	"share.save":                legacy,
	"smart.abort":               legacy,
	"smart.long":                legacy,
	"smart.schedule":            legacy,
	"smart.short":               legacy,
	"smart.unschedule":          legacy,
	"smb.mount":                 legacy,
	"smb.unmount":               legacy,
	"system.poweroff":           goNative,
	"system.reboot":             goNative,
	"system.update.check":       legacy,
	"system.update.download":    legacy,
	"system.update.install":     legacy,
	"system.update.rollback":    legacy,
	"system.update.settings":    legacy,
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
// they route to the legacy dispatcher, which authorizes or rejects them. Only an
// empty view is rejected outright here. Ordinary-user access is enforced
// separately in serve.
func routeQuery(view string) (impl, error) {
	if dst, ok := queryViews[view]; ok {
		return dst, nil
	}
	if view == "" {
		return legacy, ErrUnknownView
	}
	return legacy, nil
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
		if dst, ok := actionModules[action]; ok {
			return dst, nil
		}
		// Unlisted actions may be module extensions; the legacy dispatcher
		// resolves and authorizes them (or rejects unknowns) exactly as before.
		return legacy, nil

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
