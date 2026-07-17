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
	Name      string        `json:"name"`
	URL       string        `json:"url"`
	Ref       string        `json:"ref"`
	Ecosystem sdk.Ecosystem `json:"ecosystem"`
	Args      []string      `json:"args,omitempty"`
	Tools     []string      `json:"tools,omitempty"`
	// Detectors pins the smoke scan to the detector selector(s) whose output
	// the golden encodes (passed as --detectors). With a pinned selector set
	// the engine skips any fallback outside it, so a degraded environment
	// (e.g. a flaked java readiness probe) fails the case loudly instead of
	// silently regenerating a fallback-shaped golden.
	Detectors                string                    `json:"detectors,omitempty"`
	BenchmarkEnabled         bool                      `json:"benchmark_enabled,omitempty"`
	AdjudicatedRelationships []AdjudicatedRelationship `json:"adjudicated_relationships,omitempty"`
}

// AdjudicatedRelationship records a pinned relationship that is present in
// repository evidence but absent from a benchmark source.
type AdjudicatedRelationship struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
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
	if strings.TrimSpace(t.Detectors) != "" {
		args = append(args, "--detectors", t.Detectors)
	}
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
		seenRelationships := make(map[string]struct{}, len(target.AdjudicatedRelationships))
		for _, relationship := range target.AdjudicatedRelationships {
			from := sdk.CanonicalizePackageURL(relationship.From)
			to := sdk.CanonicalizePackageURL(relationship.To)
			if from == "" || to == "" {
				return fmt.Errorf("benchmark target %q has invalid adjudicated relationship %q -> %q", target.Name, relationship.From, relationship.To)
			}
			if strings.TrimSpace(relationship.Reason) == "" {
				return fmt.Errorf("benchmark target %q adjudicated relationship %q -> %q is missing reason", target.Name, from, to)
			}
			key := from + "\x00" + to
			if _, ok := seenRelationships[key]; ok {
				return fmt.Errorf("benchmark target %q has duplicate adjudicated relationship %q -> %q", target.Name, from, to)
			}
			seenRelationships[key] = struct{}{}
		}
	}
	return nil
}
