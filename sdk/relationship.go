package sdk

import "strings"

// DependencyRelationship describes how a dependency occurrence relates to
// the application or manifest root that owns its graph.
type DependencyRelationship string

const (
	// DependencyRelationshipDirect identifies a dependency declared by a root.
	DependencyRelationshipDirect DependencyRelationship = "direct"
	// DependencyRelationshipTransitive identifies a dependency reached through another dependency.
	DependencyRelationshipTransitive DependencyRelationship = "transitive"
	// DependencyRelationshipUnknown identifies a dependency whose parent could not be recovered.
	DependencyRelationshipUnknown DependencyRelationship = "unknown"
)

// ParseDependencyRelationship normalizes a dependency relationship value.
func ParseDependencyRelationship(value string) DependencyRelationship {
	switch DependencyRelationship(strings.ToLower(strings.TrimSpace(value))) {
	case DependencyRelationshipDirect:
		return DependencyRelationshipDirect
	case DependencyRelationshipTransitive:
		return DependencyRelationshipTransitive
	case DependencyRelationshipUnknown:
		return DependencyRelationshipUnknown
	default:
		return ""
	}
}

// RelationshipForPath returns the explicit target relationship when present,
// otherwise derives directness from a root-to-target path.
func RelationshipForPath(path []*Dependency) DependencyRelationship {
	if len(path) == 0 {
		return ""
	}
	target := path[len(path)-1]
	if target != nil && target.Relationship != "" {
		return target.Relationship
	}
	if len(path) <= 2 {
		return DependencyRelationshipDirect
	}
	return DependencyRelationshipTransitive
}

// MergeDependencyRelationship combines occurrence relationships for a merged
// graph, retaining the strongest known project relationship.
func MergeDependencyRelationship(current, next DependencyRelationship) DependencyRelationship {
	rank := func(value DependencyRelationship) int {
		switch value {
		case DependencyRelationshipDirect:
			return 3
		case DependencyRelationshipTransitive:
			return 2
		case DependencyRelationshipUnknown:
			return 1
		default:
			return 0
		}
	}
	if rank(next) > rank(current) {
		return next
	}
	return current
}
