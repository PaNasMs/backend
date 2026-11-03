package localmounts

import (
	"os"
	"panasms.local/backend/internal/systemops/folders"
	"path/filepath"
	"testing"
)

func TestPrivateStageCleanupPreservesForeignContentsAndMounts(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	s := &service{stageRoot: root, owner: os.Getuid(), mounts: func() ([]folders.LiveMount, error) { return nil, nil }}
	v := &plan{target: "/dev/sda"}
	stage := s.privateStage(v.target)
	os.Mkdir(stage, 0700)
	state := testJournal()
	state.Stage = stage
	state.StageIntent = true
	file := filepath.Join(stage, "foreign")
	os.WriteFile(file, []byte("keep"), 0600)
	if err := s.cleanupPrivateStage(v, state); err == nil {
		t.Fatal("nonempty directory removed")
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "keep" {
		t.Fatal("foreign bytes lost")
	}
	os.Remove(file)
	s.mounts = func() ([]folders.LiveMount, error) {
		return []folders.LiveMount{{ID: 19, Target: stage + "/nested"}}, nil
	}
	if err := s.cleanupPrivateStage(v, state); err == nil {
		t.Fatal("nested mount ignored")
	}
	s.mounts = func() ([]folders.LiveMount, error) { return nil, nil }
	if err := s.cleanupPrivateStage(v, state); err != nil {
		t.Fatal(err)
	}
	if state.StageIntent {
		t.Fatal("intent not cleared")
	}
	state.StageIntent = true
	if err := s.cleanupPrivateStage(v, state); err != nil {
		t.Fatal("absent recovery not idempotent", err)
	}
}
func TestPrivateStageCleanupRejectsSymlinkAndWritableDirectory(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	s := &service{stageRoot: root, owner: os.Getuid(), mounts: func() ([]folders.LiveMount, error) { return nil, nil }}
	v := &plan{target: "/dev/sda"}
	state := testJournal()
	state.Stage = s.privateStage(v.target)
	state.StageIntent = true
	os.Symlink(root, state.Stage)
	if err := s.cleanupPrivateStage(v, state); err == nil {
		t.Fatal("symlink accepted")
	}
	os.Remove(state.Stage)
	os.Mkdir(state.Stage, 0700)
	os.Chmod(state.Stage, 0777)
	if err := s.cleanupPrivateStage(v, state); err == nil {
		t.Fatal("writable stage accepted")
	}
}
