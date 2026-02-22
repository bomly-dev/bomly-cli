package sdk

import (
	"encoding/json"
	"fmt"
)

type graphJSON struct {
	Packages     []*Package       `json:"packages,omitempty"`
	Dependencies []DependencyEdge `json:"dependencies,omitempty"`
}

// DependencyEdge captures one directed relationship between package IDs.
type DependencyEdge struct {
	FromID string `json:"fromId"`
	ToID   string `json:"toId"`
}

// MarshalJSON encodes a graph as a stable transport-friendly adjacency list.
func (g *Graph) MarshalJSON() ([]byte, error) {
	if g == nil {
		return []byte("null"), nil
	}
	payload := graphJSON{
		Packages: make([]*Package, 0, g.Size()),
	}
	g.WalkPackages(func(pkg *Package) bool {
		payload.Packages = append(payload.Packages, pkg)
		return true
	})
	g.WalkRelationships(func(from, to *Package) bool {
		payload.Dependencies = append(payload.Dependencies, DependencyEdge{FromID: from.ID, ToID: to.ID})
		return true
	})
	return json.Marshal(payload)
}

// UnmarshalJSON decodes a graph from the plugin transport adjacency list.
func (g *Graph) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*g = *New()
		return nil
	}
	var payload graphJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	out := NewWithCapacity(len(payload.Packages))
	for _, pkg := range payload.Packages {
		if err := out.AddPackage(pkg); err != nil {
			return err
		}
	}
	for _, edge := range payload.Dependencies {
		if err := out.AddDependency(edge.FromID, edge.ToID); err != nil {
			return err
		}
	}
	*g = *out
	return nil
}

// MarshalJSON encodes a package manager by its canonical name.
func (m PackageManager) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.Name())
}

// UnmarshalJSON decodes a package manager from its canonical name.
func (m *PackageManager) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value == "" {
		*m = PackageManagerUnknown
		return nil
	}
	manager, err := ParsePackageManager(value)
	if err != nil {
		return fmt.Errorf("parse package manager: %w", err)
	}
	*m = manager
	return nil
}
