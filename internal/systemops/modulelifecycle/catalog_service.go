package modulelifecycle

import (
	"context"
	"encoding/json"

	"panasms.local/backend/internal/systemops"
)

type sourceRepairKey struct{}

// TrackSourceRepair records whether journal recovery may have changed state
// during a catalog request, even when a later check fails.
func TrackSourceRepair(ctx context.Context, repaired *bool) context.Context {
	return context.WithValue(ctx, sourceRepairKey{}, repaired)
}

func IsCatalogAction(action string) bool {
	switch action {
	case "module.source-add", "module.source-remove", "module.catalog-install":
		return true
	}
	return false
}

func installedCatalog(needLifecycle bool) (catalogService, error) {
	c := catalogService{
		lifecycle: lifecycle{store: installedModuleStore(), keys: installedModuleKeys},
		config:    "/etc/panasms/module-sources.json", download: newCatalogDownload(),
	}
	if !needLifecycle {
		return c, nil
	}
	var err error
	c.lifecycle, err = installedLifecycle()
	return c, err
}

func CatalogQuery(ctx context.Context, view string) (json.RawMessage, error) {
	c, err := installedCatalog(view == "module-catalog")
	if err != nil {
		return nil, err
	}
	return c.query(ctx, view)
}

func CatalogPlan(ctx context.Context, action string, p map[string]any) (json.RawMessage, error) {
	c, err := installedCatalog(action == "module.catalog-install")
	if err != nil {
		return nil, err
	}
	return c.planCatalog(ctx, action, p)
}

func (c catalogService) planCatalog(ctx context.Context, action string, p map[string]any) (json.RawMessage, error) {
	dir, err := c.catalogLock(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err = c.repairSources(ctx, dir, nil); err != nil {
		return nil, err
	}
	if action == "module.catalog-install" {
		plan, err := c.selectRelease(ctx, dir, p)
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"target": plan.target, "confirmation": plan.target, "details": plan.details, "fingerprint": plan.fingerprint})
	}
	plan, err := c.planSource(ctx, action, p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(plan.public)
}

func CatalogExecute(ctx context.Context, action string, p map[string]any, expected string, r *systemops.Reporter, authorize func() error) (json.RawMessage, error) {
	c, err := installedCatalog(action == "module.catalog-install")
	if err != nil {
		return nil, systemops.BeforeMutation(err)
	}
	return c.executeCatalog(ctx, action, p, expected, r, authorize)
}

func (c catalogService) executeCatalog(ctx context.Context, action string, p map[string]any, expected string, r *systemops.Reporter, authorize func() error) (result json.RawMessage, err error) {
	pendingMutation, repaired := false, false
	defer func() {
		if err != nil && repaired {
			err = systemops.AfterMutation(err)
		} else if err != nil && !pendingMutation {
			err = systemops.BeforeMutation(err)
		}
		cancellable(r, false)
	}()
	if authorize == nil || expected == "" {
		return nil, reject("Module operation authorization is missing")
	}
	if err = authorize(); err != nil {
		return nil, err
	}
	cancellable(r, true)
	dir, err := c.catalogLock(ctx, r)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err = c.repairSources(TrackSourceRepair(ctx, &repaired), dir, r); err != nil {
		return nil, err
	}
	stale := reject("State has changed. Review a new operation plan.")
	if action == "module.catalog-install" {
		plan, err := systemops.WithCancellation(ctx, r, func(ctx context.Context) (catalogInstallPlan, error) {
			return c.selectRelease(ctx, dir, p)
		})
		if err != nil {
			return nil, err
		}
		if expected != plan.fingerprint {
			return nil, stale
		}
		pendingMutation = true // The installer classifies pre-mutation and lifecycle errors.
		return c.install(ctx, dir, plan, r, authorize)
	}
	plan, err := systemops.WithCancellation(ctx, r, func(ctx context.Context) (sourcePlan, error) {
		return c.planSource(ctx, action, p)
	})
	if err != nil {
		return nil, err
	}
	if expected != plan.public["fingerprint"] {
		return nil, stale
	}
	if fp := plan.public["publisherFingerprint"]; plan.change.Add && fp != nil && text(p, "keyFingerprint") != fp {
		return nil, reject("Repository signing key changed. Review the repository again.")
	}
	lock, err := c.store.lock(ctx, r)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err = authorize(); err != nil {
		return nil, err
	}
	cancellable(r, false)
	if err = checkpoint(ctx, r); err != nil {
		return nil, err
	}
	pendingMutation = true
	cleanupErr, err := c.applySource(dir, plan)
	if err != nil {
		return nil, err
	}
	message := "Module repository removed"
	if plan.change.Add {
		message = "Module repository added"
	}
	body := map[string]any{"message": message}
	if cleanupErr != nil {
		body["warnings"] = []string{"Repository change saved, but cleanup is incomplete. Review the module repositories before retrying."}
	}
	return json.Marshal(body)
}

func CatalogRecovery(ctx context.Context, action string) (json.RawMessage, error) {
	c, err := installedCatalog(false)
	if err != nil {
		return nil, err
	}
	return c.recoverCatalog(ctx, action)
}

func (c catalogService) recoverCatalog(ctx context.Context, action string) (json.RawMessage, error) {
	dir, err := c.catalogLock(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err = c.repairSources(ctx, dir, nil); err != nil {
		return nil, err
	}
	var next any
	var checks []map[string]any
	message := "Review the configured module repositories. The interrupted operation has not been repeated."
	if action == "module.catalog-install" {
		if err = c.cleanCatalogStage(); err != nil {
			return nil, err
		}
		raw, err := c.inspect()
		if err != nil {
			return nil, err
		}
		var status struct{ Pending bool }
		if err = json.Unmarshal(raw, &status); err != nil {
			return nil, err
		}
		if status.Pending {
			next = "module.recover"
		}
		checks = []map[string]any{{"label": "Module transaction", "value": raw}}
		message = "Review the installed modules and recover the recorded transaction before retrying. The interrupted operation has not been repeated."
	} else {
		configured, err := c.sources()
		if err != nil {
			return nil, err
		}
		checks = []map[string]any{{"label": "Module repositories", "value": configured}}
	}
	return json.Marshal(map[string]any{"message": message, "checks": checks, "route": "/modules", "recoveryAction": next})
}
