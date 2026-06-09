package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// FailOnList is the YAML shape for fail_on values. It accepts either a
// single scalar string ("policy.fail_on: low") for backward compatibility with
// the historical single-value form, or a sequence of strings
// ("policy.fail_on: [low, reachable]") for the repeatable form. Both shapes
// normalize to []string.
type FailOnList []string

// UnmarshalYAML implements yaml.Unmarshaler so existing single-string
// configs continue to parse alongside the new sequence form.
func (l *FailOnList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return fmt.Errorf("decode fail_on scalar: %w", err)
		}
		if s == "" {
			*l = nil
			return nil
		}
		*l = FailOnList{s}
		return nil
	case yaml.SequenceNode:
		var values []string
		if err := node.Decode(&values); err != nil {
			return fmt.Errorf("decode fail_on sequence: %w", err)
		}
		*l = values
		return nil
	default:
		return fmt.Errorf("fail_on must be a string or list of strings (line %d, column %d)", node.Line, node.Column)
	}
}
