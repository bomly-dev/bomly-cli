package cargo

import (
	"strings"

	sdk "github.com/bomly-dev/bomly-sdk"
	detectorkit "github.com/bomly-dev/bomly-sdk/detectorkit"
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

// Cargo is the ecosystem where folding by identity had to be checked rather
// than assumed, so the reasoning is recorded here, next to the fold.
//
// Cargo's own package IDs are source-qualified, so one crate name and version
// can appear twice in a lockfile -- from two git remotes, or from a git remote
// and the registry -- and cargo builds both: it has no nearest-wins rule, and
// the crate that asked for each gets the one it asked for. Those really are
// two pieces of code in the artifact.
//
// They still fold into one node, and folding is the right answer rather than
// a concession. Identity is the canonical package URL (ADR-0041) and a cargo
// PURL carries no source, so both records mint the same
// "pkg:cargo/<name>@<version>" whatever they resolved from. Keeping them
// apart would produce two components with byte-identical identity -- same
// purl, same package reference, same matching result, same vulnerabilities --
// which is the duplicate-identity problem ADR-0041 exists to remove. Nothing
// is lost: Origins is union-merged, so the surviving node carries every
// source it was resolved from, which is the dependency-confusion signal two
// distinct nodes were standing in for.
//
// What would reopen this: cargo PURLs gaining a source qualifier (the three
// URL-valued keys cannot serve -- purlkit.SplitIdentity relocates them into
// origins), or matching keying on origin rather than on the package URL.
// Either makes the two genuinely distinguishable, and then they deserve
// distinct nodes.

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
		node, err := packageNode(metadataPackage{Name: pkg.Name, Version: pkg.Version, Source: pkg.Source}, pkg.Name+"@"+pkg.Version, nil, "")
		if err != nil {
			return nil, err
		}
		surviving, err := detectorkit.EnsureNode(g, node)
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
