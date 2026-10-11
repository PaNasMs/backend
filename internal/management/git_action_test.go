package management

import "testing"

func TestGitBranchSwitchIsUserOperation(t *testing.T) {
	if !userAction("file.git-switch", map[string]any{"target": "/srv/data/repo", "branch": "main"}, "alice") {
		t.Fatal("branch switching requires administrator")
	}
	if userAction("file.permissions", map[string]any{}, "alice") {
		t.Fatal("permission changes must remain administrative")
	}
}
