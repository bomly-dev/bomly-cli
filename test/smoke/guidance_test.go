// This file intentionally has no build tag, so `make test` runs it.

package smoke

import (
	"os"
	"path/filepath"
	"testing"
)

// AGENTS.md is the repository's one guidance file. Claude Code, Codex and
// the other agents read it directly, and Claude Code reads it only while no
// CLAUDE.md or CLAUDE.local.md sits beside it: adding either silently hides
// AGENTS.md from Claude. The two were kept as near-copies until that support
// landed, with nothing checking that they agreed.
func TestGuidanceLivesInAgentsMD(t *testing.T) {
	root := fixtureRepoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "AGENTS.md")); err != nil {
		t.Fatalf("AGENTS.md: %v", err)
	}
	for _, shadow := range []string{"CLAUDE.md", "CLAUDE.local.md"} {
		if _, err := os.Stat(filepath.Join(root, shadow)); err == nil {
			t.Errorf("%s exists; while it does, Claude Code ignores AGENTS.md. Put the guidance in AGENTS.md and delete %s.", shadow, shadow)
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", shadow, err)
		}
	}
}
