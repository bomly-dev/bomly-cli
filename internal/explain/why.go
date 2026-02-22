package explain

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/output"
	model "github.com/bomly-dev/bomly-cli/sdk"
)

// ErrDependencyNotFound indicates the requested package was not found.
var ErrDependencyNotFound = errors.New("dependency not found")

// Path is an alias for output.DependencyPath.
type Path = output.DependencyPath

// FindWhy resolves a target package and returns all root-to-target paths.
func FindWhy(deps *model.Graph, query string) (output.PackageRef, []Path, error) {
	target, err := resolveTarget(deps, query)
	if err != nil {
		return output.PackageRef{}, nil, err
	}

	rawPaths, err := deps.CollectPathsTo(target.ID)
	if err != nil {
		return output.PackageRef{}, nil, err
	}

	paths := make([]Path, 0, len(rawPaths))
	for _, rawPath := range rawPaths {
		paths = append(paths, toPath(rawPath.Packages, rawPath.Cyclic, rawPath.CycleTo))
	}
	sort.Slice(paths, func(i, j int) bool {
		return pathKey(paths[i]) < pathKey(paths[j])
	})

	return output.PackageFromGraphPackage(target), paths, nil
}

func resolveTarget(deps *model.Graph, query string) (*model.Package, error) {
	var exact *model.Package
	var matches []*model.Package
	for _, pkg := range deps.Packages() {
		if pkg.ID == query {
			exact = pkg
			break
		}
		if pkg.Name == query || pkg.QualifiedName() == query {
			matches = append(matches, pkg)
		}
	}
	if exact != nil {
		return exact, nil
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrDependencyNotFound, query)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].ID < matches[j].ID })
	return matches[0], nil
}

func toPath(packages []*model.Package, cyclic bool, cycleTo string) Path {
	refs := make([]output.PackageRef, 0, len(packages))
	for _, pkg := range packages {
		refs = append(refs, output.PackageFromGraphPackage(pkg))
	}
	relationship := "transitive"
	if len(refs) <= 2 {
		relationship = "direct"
	}
	introducedVia := refs[0].ID
	return Path{
		Relationship:  relationship,
		Packages:      refs,
		IntroducedVia: introducedVia,
		Cyclic:        cyclic,
		CycleTo:       cycleTo,
	}
}

func pathKey(path Path) string {
	ids := make([]string, 0, len(path.Packages))
	for _, pkg := range path.Packages {
		ids = append(ids, pkg.ID)
	}
	return strings.Join(ids, "/")
}
