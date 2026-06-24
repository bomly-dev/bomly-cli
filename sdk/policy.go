package sdk

import (
	"fmt"
	"strings"
)

// FailOnKind classifies one --fail-on constraint.
type FailOnKind string

const (
	// SeverityConstraint matches when a finding's severity is at or above
	// the constraint Value (any|low|medium|high|critical).
	SeverityConstraint FailOnKind = "severity"
	// ReachabilityConstraint matches when a vulnerability's reachability
	// status equals the constraint Value (currently only "reachable").
	ReachabilityConstraint FailOnKind = "reachability"
	// ExploitabilityConstraint matches when a vulnerability has known
	// exploitation metadata.
	ExploitabilityConstraint FailOnKind = "exploitability"
)

// FailOnConstraint is one parsed --fail-on value. The policy auditor
// evaluates a vulnerability against an AND-set of constraints; only
// vulnerabilities satisfying every constraint become Findings.
type FailOnConstraint struct {
	Kind  FailOnKind
	Value string
}

// String returns a stable string form for the constraint, suitable for
// debug logs and error messages.
func (c FailOnConstraint) String() string {
	if c.Kind == "" && c.Value == "" {
		return ""
	}
	return string(c.Kind) + ":" + c.Value
}

// ReachabilityValueReachable constraint values currently supported.
const (
	ReachabilityValueReachable = "reachable"
)

// ExploitabilityValueExploitable constraint values currently supported.
const (
	ExploitabilityValueExploitable = "exploitable"
)

var validSeverityValues = map[SeverityLevel]struct{}{
	SeverityAny:      {},
	SeverityLow:      {},
	SeverityMedium:   {},
	SeverityHigh:     {},
	SeverityCritical: {},
}

var validReachabilityValues = map[string]struct{}{
	ReachabilityValueReachable: {},
}

var validExploitabilityValues = map[string]struct{}{
	ExploitabilityValueExploitable: {},
}

// ParseFailOn parses one raw --fail-on value into a typed constraint.
// Severity tokens (any|low|medium|high|critical) yield a SeverityConstraint.
// "reachable" yields a ReachabilityConstraint. "exploitable" yields an
// ExploitabilityConstraint. Empty input returns the zero value with no error
// so callers can treat empty repeats as no-ops.
func ParseFailOn(raw string) (FailOnConstraint, error) {
	normalized := ParseSeverityLevel(raw)
	if normalized == SeverityUnknown && strings.TrimSpace(raw) == "" {
		return FailOnConstraint{}, nil
	}
	if _, ok := validSeverityValues[normalized]; ok {
		return FailOnConstraint{Kind: SeverityConstraint, Value: string(normalized)}, nil
	}
	rawNormalized := strings.ToLower(strings.TrimSpace(raw))
	if _, ok := validReachabilityValues[rawNormalized]; ok {
		return FailOnConstraint{Kind: ReachabilityConstraint, Value: rawNormalized}, nil
	}
	if _, ok := validExploitabilityValues[rawNormalized]; ok {
		return FailOnConstraint{Kind: ExploitabilityConstraint, Value: rawNormalized}, nil
	}
	return FailOnConstraint{}, fmt.Errorf("unsupported --fail-on value %q (accepted: any, low, medium, high, critical, reachable, exploitable)", raw)
}

// ParseFailOnList parses every raw value, skipping empty entries. It returns
// an aggregate error if any value is invalid; valid constraints are still
// returned alongside the error so callers can surface partial diagnostics.
func ParseFailOnList(raws []string) ([]FailOnConstraint, error) {
	out := make([]FailOnConstraint, 0, len(raws))
	var firstErr error
	for _, raw := range raws {
		c, err := ParseFailOn(raw)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if c.Kind == "" {
			continue
		}
		out = append(out, c)
	}
	return out, firstErr
}

// SeverityRank returns a comparable rank for a severity string.
// Unknown / empty values rank below "low". The GitHub-aligned levels share the
// ladder with the CVSS bands: error ≡ high, warning ≡ medium, note ≡ low.
func SeverityRank(severity SeverityLevel) int {
	switch ParseSeverityLevel(string(severity)) {
	case SeverityCritical:
		return 4
	case SeverityHigh, SeverityError:
		return 3
	case SeverityMedium, SeverityWarning:
		return 2
	case SeverityLow, SeverityNote:
		return 1
	default:
		return 0
	}
}

// SeverityMeets reports whether candidate's severity is at or above
// threshold. Threshold "any" matches every candidate, including unknown.
func SeverityMeets(candidate SeverityLevel, threshold string) bool {
	t := ParseSeverityLevel(threshold)
	if t == SeverityAny || strings.TrimSpace(threshold) == "" {
		return true
	}
	return SeverityRank(candidate) >= SeverityRank(t)
}

// MatchesConstraints evaluates one vulnerability against a set of
// constraints (AND semantics). When constraints is empty, every
// vulnerability matches (the historical behavior of `--audit` without
// `--fail-on`).
func (v Vulnerability) MatchesConstraints(constraints []FailOnConstraint) bool {
	for _, c := range constraints {
		switch c.Kind {
		case SeverityConstraint:
			if !SeverityMeets(v.ParsedSeverity, c.Value) {
				return false
			}
		case ReachabilityConstraint:
			// Currently only "reachable" is supported. nil reachability
			// (no analyzer ran) does NOT match — the analyzer must have
			// affirmatively determined reachability.
			if v.Reachability == nil || v.Reachability.Status != ReachabilityReachable {
				return false
			}
		case ExploitabilityConstraint:
			if !v.IsExploitable() {
				return false
			}
		default:
			// Unknown kinds are treated as no-op rather than as
			// rejection so future constraint kinds can be added without
			// breaking older auditor behavior.
		}
	}
	return true
}
