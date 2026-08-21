package cargo

import (
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-sdk"
)

// lockIndex assigns node IDs to Cargo.lock records and resolves the lockfile's
// dependency strings back to them.
//
// Cargo.lock records are source-qualified: the same name@version can appear
// once from a registry and once from a git remote (renamed dependencies), and
// the deps lists disambiguate exactly when needed -- a bare "name" where the
// name is unique, "name version" where versions differ, and
// "name version (source)" where sources differ. Folding such records under one
// name@version ID conflated their edges and could publish one occurrence's
// repository for code fetched from the other, so each distinct source keeps a
// distinct node.
type lockIndex struct {
	// nodeID is keyed by name, name@version, and the full qualified form, so
	// dependency strings resolve at whatever precision the lockfile wrote.
	// Ambiguous keys (a bare name naming several records) resolve to the
	// first record in file order, deterministically -- cargo only writes a
	// bare reference when the name is unambiguous.
	nodeID map[string]string
}

// buildLockIndex creates graph nodes for every lock record (skipping the root
// package) and returns the index that resolves dependency strings to them.
func buildLockIndex(g *sdk.Graph, packages []lockPackage, rootName string) (*lockIndex, error) {
	index := &lockIndex{nodeID: make(map[string]string, len(packages)*3)}
	for _, pkg := range packages {
		if pkg.Name == rootName {
			continue
		}
		node := packageNode(metadataPackage{Name: pkg.Name, Version: pkg.Version, Source: pkg.Source}, pkg.Name+"@"+pkg.Version, nil)
		surviving, err := detectors.EnsureNode(g, node)
		if err != nil {
			return nil, err
		}
		if surviving != node && strings.TrimSpace(surviving.ResolvedURL) != strings.TrimSpace(pkg.Source) {
			// A second resolution of the same name@version. The lockfile
			// asserts they are different (distinct source fields), so both
			// stay, the newcomer under an opaque occurrence ID.
			node.ID = detectors.OccurrenceID(node.ID, strings.TrimSpace(pkg.Source))
			if surviving, err = detectors.EnsureNode(g, node); err != nil {
				return nil, err
			}
		}
		index.record(pkg, surviving.ID)
	}
	return index, nil
}

// record registers every reference form that can name this occurrence,
// first-wins so bare forms stay deterministic in file order.
func (x *lockIndex) record(pkg lockPackage, nodeID string) {
	for _, key := range []string{
		pkg.Name,
		pkg.Name + " " + pkg.Version,
		strings.TrimSpace(pkg.Name + " " + pkg.Version + " (" + pkg.Source + ")"),
	} {
		if _, taken := x.nodeID[key]; !taken {
			x.nodeID[key] = nodeID
		}
	}
}

// resolve maps a Cargo.lock dependency string to the node it names, at
// whatever precision the lockfile wrote it.
func (x *lockIndex) resolve(dep string) (string, bool) {
	id, ok := x.nodeID[strings.TrimSpace(dep)]
	return id, ok
}
