package accounts

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

func homeFileMatches(path string, expected []uint64) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, reject("Home maintenance marker changed; data was preserved")
	}
	st := info.Sys().(*syscall.Stat_t)
	return len(expected) == 0 || slices.Equal([]uint64{uint64(st.Dev), st.Ino}, expected), nil
}

func (s *homeService) cleanNologinTemp(state *homeJournal) error {
	if state.NologinTemp == "" {
		return nil
	}
	owned, err := homeFileMatches(state.NologinTemp, state.NologinIdentity)
	if err != nil {
		return err
	}
	if owned {
		return os.Remove(state.NologinTemp)
	}
	return nil
}

func (s *homeService) createNologin(state *homeJournal) error {
	f, err := os.CreateTemp(filepath.Dir(s.nologin), ".panasms-home-nologin-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0644); err != nil {
		return err
	}
	if _, err := f.WriteString(state.Nologin); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st := info.Sys().(*syscall.Stat_t)
	state.NologinIdentity = []uint64{uint64(st.Dev), st.Ino}
	state.NologinTemp = f.Name()
	// Record ownership before publishing a complete marker, including across a crash.
	if err := s.save(state); err != nil {
		return err
	}
	return os.Link(f.Name(), s.nologin)
}
