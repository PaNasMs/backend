package localmounts

import (
	"context"
	"panasms.local/backend/internal/systemops"
	"panasms.local/backend/internal/systemops/storagebase"
	"strings"
)

func (s *service) open(ctx context.Context, v *plan, p map[string]any, pin *storagebase.PinnedDevice, state *transaction, save func(*transaction) error, r *systemops.Reporter) (map[string]any, bool, error) {
	mode := text(p, "mode")
	if mode == "" {
		mode = "auto"
	}
	readonly := mode == "readonly" || (mode == "auto" && p["readOnly"] == true)
	choice := func(reason string) map[string]any {
		return map[string]any{"needsChoice": true, "reason": reason, "repairAvailable": s.checkAvailable(v.fs), "message": "Choose how to open the volume before mounting"}
	}
	if v.stale != nil {
		if !staleBlockMount(*v.stale) {
			return nil, false, reject("The disconnected volume state changed; review a new operation plan")
		}
		if err := step(state, "unmount-disconnected-volume", save, func() error { return storagebase.UnmountPinned(v.stale.Target, *v.stale) }); err != nil {
			return nil, false, err
		}
	}
	detach := mode == "repair" || mode == "repair-only"
	if len(v.selected) > 0 && !detach {
		m := v.selected[0]
		actualRO := strings.Contains(","+m.Options+",", ",ro,")
		if readonly && !actualRO {
			detach = true
		} else if !readonly && actualRO {
			return choice("The volume is read-only, possibly due to file system errors. Choose repair or read-only access."), true, nil
		} else {
			return map[string]any{"point": m.Target, "readOnly": actualRO}, true, nil
		}
	}
	if detach {
		all, err := s.mounts()
		if err != nil {
			return nil, false, err
		}
		if err = s.blockers(ctx, v.selected, all); err != nil {
			return nil, false, err
		}
		for _, mount := range v.selected {
			m := mount
			if err = step(state, "unmount:"+m.Target, save, func() error { return storagebase.UnmountPinned(m.Target, m) }); err != nil {
				return nil, false, err
			}
		}
	}
	if err := refreshRemountTarget(v); err != nil {
		return nil, false, err
	}
	fresh, err := s.load(ctx)
	if err != nil {
		return nil, false, err
	}
	if err = fresh.Unused(v.target, false); err != nil {
		return nil, false, err
	}
	if err = pin.Verify(); err != nil {
		return nil, false, err
	}
	if !readonly {
		if !s.checkAvailable(v.fs) {
			return choice("For " + v.fs + " automatic checking is unavailable. You can mount the volume read-only."), true, nil
		}
		clean, reason := false, ""
		repair := mode == "repair" || mode == "repair-only"
		if err = step(state, "filesystem-check", save, func() error { clean, reason = s.checkFilesystem(ctx, pin.Path(), v.fs, repair, r); return nil }); err != nil {
			return nil, false, err
		}
		if err = saveHealth("/run/panasms-filesystems", 0, pin.Identity, clean, reason, s.checkAvailable(v.fs)); err != nil {
			return nil, false, err
		}
		if !clean {
			return choice(reason), true, nil
		}
	}
	if mode == "repair-only" {
		return map[string]any{"repaired": true, "message": "Errors repaired. The volume remains unmounted."}, true, nil
	}
	if err = s.attach(ctx, v, pin, state, save, r); err != nil {
		return choice("Could not mount volume: " + err.Error()), false, nil
	}
	rows, err := s.mounts()
	if err != nil {
		return nil, false, err
	}
	for _, m := range rows {
		if m.ID == state.MountID && !readonly && strings.Contains(","+m.Options+",", ",ro,") {
			return choice("Linux mounted the volume read-only. A file system check is required."), true, nil
		}
	}
	return map[string]any{"point": v.point, "readOnly": readonly}, true, nil
}
