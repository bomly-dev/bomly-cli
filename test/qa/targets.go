package qa

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ScanTarget describes one repository-backed smoke scan case that may also be
// used by the dependency graph QA workflow.
type ScanTarget struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	Ref       string   `json:"ref"`
	Args      []string `json:"args,omitempty"`
	Tools     []string `json:"tools,omitempty"`
	QAEnabled bool     `json:"qa_enabled,omitempty"`
}

// DefaultTargetsPath returns the repository-relative shared scan target path.
func DefaultTargetsPath(repoRoot string) string {
	return filepath.Join(repoRoot, "test", "smoke", "testdata", "scan_targets.json")
}

// LoadScanTargets reads shared smoke/QA scan targets from path.
func LoadScanTargets(path string) ([]ScanTarget, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read scan targets: %w", err)
	}
	var targets []ScanTarget
	if err := json.Unmarshal(raw, &targets); err != nil {
		return nil, fmt.Errorf("parse scan targets: %w", err)
	}
	if err := validateScanTargets(targets); err != nil {
		return nil, err
	}
	return targets, nil
}

// QAScanTargets filters targets to those enabled for dependency graph QA.
func QAScanTargets(targets []ScanTarget) []ScanTarget {
	out := make([]ScanTarget, 0, len(targets))
	for _, target := range targets {
		if target.QAEnabled {
			out = append(out, target)
		}
	}
	return out
}

// SmokeArgs returns the bomly scan arguments for the pinned smoke test case.
func (t ScanTarget) SmokeArgs() []string {
	args := []string{"scan", "--url", t.URL}
	if t.Ref != "" {
		args = append(args, "--ref", t.Ref)
	}
	args = append(args, "--format", "json")
	args = append(args, t.Args...)
	return args
}

// QAArgs returns extra bomly scan arguments safe to reuse for QA HEAD scans.
func (t ScanTarget) QAArgs() []string {
	out := make([]string, len(t.Args))
	copy(out, t.Args)
	return out
}

func validateScanTargets(targets []ScanTarget) error {
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if target.Name == "" {
			return fmt.Errorf("scan target is missing name")
		}
		if _, ok := seen[target.Name]; ok {
			return fmt.Errorf("duplicate scan target %q", target.Name)
		}
		seen[target.Name] = struct{}{}
		if target.URL == "" {
			return fmt.Errorf("scan target %q is missing url", target.Name)
		}
		if target.Ref == "" {
			return fmt.Errorf("scan target %q is missing ref", target.Name)
		}
	}
	return nil
}
