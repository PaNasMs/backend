package localmounts

import (
	"os"
	"panasms.local/backend/internal/systemops/storagebase"
	"path/filepath"
	"syscall"
)

func privateStage(target string) string {
	return filepath.Join("/run/panasms-local-mounts", storagebase.Hash(target)+".stage")
}
func (s *service) cleanupPrivateStage(v *plan, state *transaction) error {
	if !state.StageIntent {
		state.MountID = 0
		return nil
	}
	if state.Stage != privateStage(v.target) {
		return reject("Private mount stage identity is invalid")
	}
	rows, err := s.mounts()
	if err != nil {
		return err
	}
	for _, m := range rows {
		if within(m.Target, state.Stage) {
			return reject("A private stage is still mounted; inspect recovery before removing it")
		}
	}
	if err = storagebase.SecureDirectory(filepath.Dir(state.Stage), s.owner, false); err != nil {
		if os.IsNotExist(err) {
			state.StageIntent = false
			state.MountID = 0
			return nil
		}
		return err
	}
	st, err := os.Lstat(state.Stage)
	if os.IsNotExist(err) {
		state.StageIntent = false
		state.MountID = 0
		return nil
	}
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || int(st.Sys().(*syscall.Stat_t).Uid) != s.owner {
		return reject("Private mount stage permissions are unsafe")
	}
	if err = os.Remove(state.Stage); err != nil {
		return err
	}
	state.StageIntent = false
	state.MountID = 0
	return nil
}
