package node_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node/bun"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-sdk"
)

// originOf returns the origin a node publishes, or the zero value when it has
// none, so cases can compare plain structs.
func originOf(dep *sdk.Dependency) sdk.DependencyOrigin {
	if dep == nil {
		return sdk.DependencyOrigin{}
	}
	if origin := dep.Origin.Normalized(); origin != nil {
		return *origin
	}
	return sdk.DependencyOrigin{}
}

// requireArtifactOrigin asserts a package asserts exactly the given artifact.
func requireArtifactOrigin(t *testing.T, g *sdk.Graph, name, version, want string) {
	t.Helper()
	origin := originOf(requirePackage(t, g, name, version))
	if origin.ArtifactURL != want {
		t.Errorf("%s@%s artifact origin = %q, want %q", name, version, origin.ArtifactURL, want)
	}
	if origin.Repository != "" {
		t.Errorf("%s@%s also asserted a repository %q", name, version, origin.Repository)
	}
}

// requireNoOrigin asserts a package publishes no location at all.
func requireNoOrigin(t *testing.T, g *sdk.Graph, name, version string) {
	t.Helper()
	if origin := originOf(requirePackage(t, g, name, version)); !origin.Empty() {
		t.Errorf("%s@%s asserted an origin it should not have: %+v", name, version, origin)
	}
}

func TestNPMLockfileOriginIsTheRegistryTarball(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v3"))
	if err != nil {
		t.Fatal(err)
	}
	requireArtifactOrigin(t, g, "lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
	requireArtifactOrigin(t, g, "jest", "29.7.0", "https://registry.npmjs.org/jest/-/jest-29.7.0.tgz")
}

// A v1 lockfile has no packages map, so it resolves through the flat
// dependencies tree. It records the same tarball URLs, and must publish them.
func TestNPMLockfileV1OriginIsTheRegistryTarball(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v1"))
	if err != nil {
		t.Fatal(err)
	}
	requireArtifactOrigin(t, g, "react", "18.2.0", "https://registry.npmjs.org/react/-/react-18.2.0.tgz")
	requireArtifactOrigin(t, g, "loose-envify", "1.4.0", "https://registry.npmjs.org/loose-envify/-/loose-envify-1.4.0.tgz")
}

// Workspace members are local directories. npm records that directory as the
// member's "resolved" value, which must never reach an SBOM.
func TestNPMWorkspaceMembersAssertNoOrigin(t *testing.T) {
	result, err := (npm.LockfileDetector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: fixture("npm-v3-workspaces")})
	if err != nil {
		t.Fatal(err)
	}
	g, err := result.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatal(err)
	}
	requireArtifactOrigin(t, g, "lodash", "4.17.21", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz")
	requireNoOrigin(t, g, "web", "0.2.0")
	requireNoOrigin(t, g, "lib", "1.0.0")
}

func TestPNPMLockfileOriginIsTheResolutionTarball(t *testing.T) {
	g, err := resolveLockfileGraph(t, pnpm.LockfileDetector{}, fixture("pnpm-v5"))
	if err != nil {
		t.Fatal(err)
	}
	requireArtifactOrigin(t, g, "react", "18.2.0", "https://registry.npmjs.org/react/-/react-18.2.0.tgz")
}

// pnpm v9 records only an integrity hash for registry packages. A hash is not a
// location, and the registry root is not this package's origin, so there is
// nothing to assert.
func TestPNPMIntegrityOnlyEntriesAssertNoOrigin(t *testing.T) {
	result, err := (pnpm.LockfileDetector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: fixture("pnpm-v9-workspaces")})
	if err != nil {
		t.Fatal(err)
	}
	g, err := result.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatal(err)
	}
	requireNoOrigin(t, g, "lodash", "4.17.21")
	requireNoOrigin(t, g, "shared-transitive", "2.0.0")
}

// Yarn Classic appends the package checksum to the tarball URL as a fragment.
// It identifies the file's contents, not a location, so it is dropped.
func TestYarnClassicOriginDropsTheChecksumFragment(t *testing.T) {
	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, fixture("yarn-v1"))
	if err != nil {
		t.Fatal(err)
	}
	requireArtifactOrigin(t, g, "react", "18.2.0", "https://registry.npmjs.org/react/-/react-18.2.0.tgz")
	requireArtifactOrigin(t, g, "js-tokens", "4.0.0", "https://registry.npmjs.org/js-tokens/-/js-tokens-4.0.0.tgz")
}

// Berry lockfiles record a resolution identity rather than a fetched URL.
func TestYarnBerryAssertsNoOrigin(t *testing.T) {
	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, fixture("yarn-berry"))
	if err != nil {
		t.Fatal(err)
	}
	requireNoOrigin(t, g, "react", "18.2.0")
}

func TestBunLockfileOriginIsTheRegistryTarball(t *testing.T) {
	result, err := (bun.LockfileDetector{}).ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: fixture("bun-v1-workspaces")})
	if err != nil {
		t.Fatal(err)
	}
	g, err := result.Graphs.ConsolidatedGraph()
	if err != nil {
		t.Fatal(err)
	}
	requireArtifactOrigin(t, g, "is-number", "7.0.0", "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz")
	requireNoOrigin(t, g, "workspace:packages/lib", "")
}

// Yarn Classic can pin one name@version to different tarballs under different
// selectors. Both stay as distinct occurrences with their own origins.
func TestYarnDuplicateResolvedEntriesStayDistinct(t *testing.T) {
	dir := t.TempDir()
	lock := `# yarn.lock classic (v1) format

shared@^2.0.0:
  version "2.0.0"
  resolved "https://registry.npmjs.org/shared/-/shared-2.0.0.tgz"

"shared@corp:^2.0.0":
  version "2.0.0"
  resolved "https://npm.corp/mirror/shared/-/shared-2.0.0.tgz"
`
	if err := os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"demo","version":"1.0.0","dependencies":{"shared":"^2.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	origins := map[string]int{}
	g.WalkNodes(func(dep *sdk.Dependency) bool {
		if dep.Name == "shared" {
			origins[originOf(dep).ArtifactURL]++
		}
		return true
	})
	if len(origins) != 2 ||
		origins["https://registry.npmjs.org/shared/-/shared-2.0.0.tgz"] != 1 ||
		origins["https://npm.corp/mirror/shared/-/shared-2.0.0.tgz"] != 1 {
		t.Fatalf("shared occurrences = %v, want both tarballs as distinct nodes", origins)
	}
}
