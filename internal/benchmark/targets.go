// Package benchmark owns Bomly's hidden local dependency-graph benchmark.
package benchmark

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/bomly-dev/bomly-cli/sdk"
)

//go:embed testdata/scan_targets.json
var embeddedTargets []byte

// Target describes one repository-backed smoke and benchmark case.
type Target struct {
	Name             string        `json:"name"`
	URL              string        `json:"url"`
	Ref              string        `json:"ref"`
	Ecosystem        sdk.Ecosystem `json:"ecosystem"`
	Args             []string      `json:"args,omitempty"`
	Tools            []string      `json:"tools,omitempty"`
	BenchmarkEnabled bool          `json:"benchmark_enabled,omitempty"`
}

// LoadTargets reads targets from path, or from the embedded manifest when path is empty.
func LoadTargets(path string) ([]Target, error) {
	raw := embeddedTargets
	if strings.TrimSpace(path) != "" {
		var err error
		raw, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read benchmark targets: %w", err)
		}
	}
	var targets []Target
	if err := json.Unmarshal(raw, &targets); err != nil {
		return nil, fmt.Errorf("parse benchmark targets: %w", err)
	}
	if err := validateTargets(targets); err != nil {
		return nil, err
	}
	return targets, nil
}

// Targets filters targets to those enabled for the hidden benchmark.
func Targets(targets []Target) []Target {
	out := make([]Target, 0, len(targets))
	for _, target := range targets {
		if target.BenchmarkEnabled {
			out = append(out, target)
		}
	}
	return out
}

// SmokeArgs returns the scan arguments for the target's pinned smoke-test revision.
func (t Target) SmokeArgs() []string {
	args := []string{"scan", "--url", t.URL, "--ref", t.Ref, "--format", "json"}
	args = append(args, "--ecosystems", string(t.Ecosystem))
	args = append(args, t.Args...)
	return args
}

func validateTargets(targets []Target) error {
	seen := make(map[string]struct{}, len(targets))
	for idx := range targets {
		target := &targets[idx]
		if strings.TrimSpace(target.Name) == "" {
			return fmt.Errorf("benchmark target is missing name")
		}
		if target.Name == "." || target.Name == ".." || strings.ContainsAny(target.Name, `/\`) {
			return fmt.Errorf("benchmark target %q name must not contain path separators", target.Name)
		}
		if _, ok := seen[target.Name]; ok {
			return fmt.Errorf("duplicate benchmark target %q", target.Name)
		}
		seen[target.Name] = struct{}{}
		if strings.TrimSpace(target.URL) == "" {
			return fmt.Errorf("benchmark target %q is missing url", target.Name)
		}
		if strings.TrimSpace(target.Ref) == "" {
			return fmt.Errorf("benchmark target %q is missing ref", target.Name)
		}
		ecosystem, err := sdk.ParseEcosystem(string(target.Ecosystem))
		if err != nil {
			return fmt.Errorf("benchmark target %q ecosystem: %w", target.Name, err)
		}
		target.Ecosystem = ecosystem
	}
	return nil
}
