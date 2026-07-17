package benchmark

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/sdk"
)

func TestLoadTargetsUsesEmbeddedManifest(t *testing.T) {
	targets, err := LoadTargets("")
	if err != nil {
		t.Fatalf("LoadTargets() error = %v", err)
	}
	if len(targets) == 0 {
		t.Fatal("expected embedded targets")
	}
	if targets[0].Name != "scan-go" || targets[0].Ecosystem != sdk.EcosystemGo {
		t.Fatalf("unexpected first target: %#v", targets[0])
	}
}

func TestLoadTargetsAndSmokeArgs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	raw := []byte(`[{"name":"scan-npm","url":"https://github.com/example/npm","ref":"v1","ecosystem":"npm","benchmark_enabled":true}]`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	targets, err := LoadTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	args := targets[0].SmokeArgs()
	if got := args[len(args)-1]; got != "npm" {
		t.Fatalf("last arg = %q, want npm: %#v", got, args)
	}
}

func TestFilterTargetsByEcosystem(t *testing.T) {
	targets := []Target{{Name: "npm", Ecosystem: sdk.EcosystemNPM}, {Name: "go", Ecosystem: sdk.EcosystemGo}}
	filtered := filterTargetsByEcosystem(targets, []sdk.Ecosystem{sdk.EcosystemNPM})
	if len(filtered) != 1 || filtered[0].Name != "npm" {
		t.Fatalf("filtered = %#v", filtered)
	}
}

func TestLoadTargetsRejectsUnsafeCaseName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	raw := []byte(`[{"name":"../outside","url":"https://github.com/example/npm","ref":"v1","ecosystem":"npm","benchmark_enabled":true}]`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargets(path); err == nil {
		t.Fatal("LoadTargets() expected unsafe name error")
	}
}

func TestLoadTargetsRejectsUnexplainedAdjudication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.json")
	raw := []byte(`[{"name":"scan-npm","url":"https://github.com/example/npm","ref":"v1","ecosystem":"npm","adjudicated_relationships":[{"from":"pkg:npm/a@1.0.0","to":"pkg:npm/b@1.0.0"}]}]`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTargets(path); err == nil {
		t.Fatal("LoadTargets() expected missing adjudication reason error")
	}
}
