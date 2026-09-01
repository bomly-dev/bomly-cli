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

// qualifiedLockKey renders a lock record in the fully qualified reference form
// Cargo.lock itself uses ("name version (source)", trimmed when the record has
// no source). Both recording and resolving go through this one rendering so a
// record always finds its own node.
func qualifiedLockKey(pkg lockPackage) string {
	return strings.TrimSpace(pkg.Name + " " + pkg.Version + " (" + pkg.Source + ")")
}

// isProjectLockRecord reports whether pkg could be the lock record of the
// project's own package described by manifest. Matching by name alone
// conflated members with unrelated same-named crates (issue #399); the
// project's own records are path-local, so they never carry a source, and
// they must match the manifest's declared version. Workspace version
// inheritance can leave the manifest without a version -- callers resolve the
// inherited [workspace.package] version first where the root manifest is
// available, and projectLockRecord refuses to guess between candidates that
// remain ambiguous without one.
func isProjectLockRecord(pkg lockPackage, manifest cargoManifest) bool {
	if manifest.Name == "" || pkg.Name != manifest.Name {
		return false
	}
	if strings.TrimSpace(pkg.Source) != "" {
		return false
	}
	return manifest.Version == "" || pkg.Version == manifest.Version
}

// projectLockRecord returns the lock record owned by the project package
// described by manifest, or a record synthesized from the manifest when the
// lockfile holds none. When the manifest declares no version and several
// source-less records share its name at different versions, no candidate is
// claimed: guessing by file order could hand a member another path package's
// identity, and leaving every record in the graph is the recoverable error.
func projectLockRecord(packages []lockPackage, manifest cargoManifest) lockPackage {
	matched := false
	var record lockPackage
	for _, pkg := range packages {
		if !isProjectLockRecord(pkg, manifest) {
			continue
		}
		if !matched {
			record, matched = pkg, true
			continue
		}
		if pkg.Version != record.Version {
			return lockPackage{Name: manifest.Name, Version: manifest.Version}
		}
	}
	if matched {
		return record
	}
	return lockPackage{Name: manifest.Name, Version: manifest.Version}
}

// lockDependencyRefs indexes a lock record's dependency reference strings by
// crate name, so a manifest's bare dependency name resolves at the precision
// the lockfile wrote -- "name", "name version", or "name version (source)".
func lockDependencyRefs(pkg lockPackage) map[string]string {
	refs := make(map[string]string, len(pkg.Dependencies))
	for _, ref := range pkg.Dependencies {
		fields := strings.Fields(ref)
		if len(fields) == 0 {
			continue
		}
		if _, ok := refs[fields[0]]; !ok {
			refs[fields[0]] = ref
		}
	}
	return refs
}

// buildLockIndex creates graph nodes for every lock record except the root
// package's claimed record, and returns the index that resolves dependency
// strings to them.
func buildLockIndex(g *sdk.Graph, packages []lockPackage, rootRecord lockPackage) (*lockIndex, error) {
	index := &lockIndex{nodeID: make(map[string]string, len(packages)*3)}
	rootKey := qualifiedLockKey(rootRecord)
	for _, pkg := range packages {
		if qualifiedLockKey(pkg) == rootKey {
			continue
		}
		node, err := packageNode(metadataPackage{Name: pkg.Name, Version: pkg.Version, Source: pkg.Source}, pkg.Name+"@"+pkg.Version, nil)
		if err != nil {
			return nil, err
		}
		surviving, err := detectors.EnsureNode(g, node)
		if err != nil {
			return nil, err
		}
		index.record(pkg, surviving.NodeID())
	}
	return index, nil
}

// sourceWithoutPrecise strips the resolved-commit fragment from a git source.
// A record's source pins the commit ("git+URL#<sha>"), but Cargo qualifies
// dependency references with the source identity only ("name version
// (git+URL)") -- the fragment is not part of it.
func sourceWithoutPrecise(source string) string {
	source = strings.TrimSpace(source)
	if !strings.HasPrefix(source, "git+") {
		return source
	}
	if cut := strings.IndexByte(source, '#'); cut >= 0 {
		return source[:cut]
	}
	return source
}

// record registers every reference form that can name this occurrence,
// first-wins so bare forms stay deterministic in file order.
func (x *lockIndex) record(pkg lockPackage, nodeID string) {
	keys := []string{
		pkg.Name,
		pkg.Name + " " + pkg.Version,
		qualifiedLockKey(pkg),
	}
	// Dependency references qualify git sources without the precise commit
	// fragment; register that rendering too, or references to same-named
	// same-versioned git crates would resolve to nothing.
	if stripped := sourceWithoutPrecise(pkg.Source); stripped != strings.TrimSpace(pkg.Source) {
		keys = append(keys, qualifiedLockKey(lockPackage{Name: pkg.Name, Version: pkg.Version, Source: stripped}))
	}
	for _, key := range keys {
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
