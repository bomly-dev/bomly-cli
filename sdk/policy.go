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
	// SourceChangeConstraint matches package-auditor findings for dependency
	// source changes in a diff.
	SourceChangeConstraint FailOnKind = "source-change"
)

// FailOnConstraint is one parsed --fail-on value. Vulnerability constraints
// form an AND-set. Other finding types may define independent gates, such as
// a dependency source change in a diff.
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

// SourceChangeValue is the supported dependency source-change constraint.
const (
	SourceChangeValue = "source-change"
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

var validSourceChangeValues = map[string]struct{}{
	SourceChangeValue: {},
}

// ParseFailOn parses one raw --fail-on value into a typed constraint.
// Severity tokens (any|low|medium|high|critical) yield a SeverityConstraint.
// "reachable" yields a ReachabilityConstraint. "exploitable" yields an
// ExploitabilityConstraint. "source-change" yields a SourceChangeConstraint.
// Empty input returns the zero value with no error so callers can treat empty
// repeats as no-ops.
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
	if _, ok := validSourceChangeValues[rawNormalized]; ok {
		return FailOnConstraint{Kind: SourceChangeConstraint, Value: rawNormalized}, nil
	}
	return FailOnConstraint{}, fmt.Errorf("unsupported --fail-on value %q (accepted: any, low, medium, high, critical, reachable, exploitable, source-change)", raw)
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

// MatchesConstraints evaluates one vulnerability against the vulnerability
// constraints in an AND-set. Source-change constraints apply only to package
// findings and are ignored here. When constraints is empty, every
// vulnerability matches (the historical behavior of `--audit` without
// `--fail-on`). A list containing only non-vulnerability constraints also
// leaves vulnerability matching unchanged.
func (v Vulnerability) MatchesConstraints(constraints []FailOnConstraint) bool {
	if len(constraints) == 0 {
		return true
	}
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
		case SourceChangeConstraint:
			// Source changes are evaluated by the package auditor against
			// dependency detail transitions, not vulnerabilities.
		default:
			// Unknown kinds are treated as no-op rather than as
			// rejection so future constraint kinds can be added without
			// breaking older auditor behavior.
		}
	}
	return true
}
