package matchers

import "github.com/bomly-dev/bomly-cli/sdk"

// RegistryPackagesForGraph seeds the PURL-keyed package registry from the
// dependency graph and returns the registry packages that matchers should
// enrich. Each dependency node is linked to its package via PackageRef (PURL);
// packages are deduplicated by PURL so a matcher enriches each unique package
// once regardless of how many dependency instances reference it.
//
// When a target is set, only the target dependency is considered.
func RegistryPackagesForGraph(g *sdk.Graph, reg *sdk.PackageRegistry, target *sdk.Dependency) []*sdk.Package {
	if g == nil || reg == nil {
		return nil
	}

	deps := g.Nodes()
	if target != nil {
		deps = []*sdk.Dependency{target}
	}

	seen := make(map[string]struct{}, len(deps))
	out := make([]*sdk.Package, 0, len(deps))
	for _, dep := range deps {
		if dep == nil {
			continue
		}
		purl := sdk.CanonicalPackageURLFromDependency(dep)
		if purl == "" {
			continue
		}
		dep.PackageRef = purl
		if _, ok := seen[purl]; ok {
			continue
		}
		seen[purl] = struct{}{}

		pkg, ok := reg.Get(purl)
		if !ok {
			pkg = reg.Add(sdk.PackageFromDependency(dep))
		}
		if pkg != nil {
			out = append(out, pkg)
		}
	}
	return out
}
