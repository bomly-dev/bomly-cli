package attestation

import (
	"os/exec"
	"strings"
	"testing"
)

func runCommandForAttestationTest(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is required for this test: %v", name, err)
	}
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, string(output))
	}
	return strings.TrimSpace(string(output))
}
