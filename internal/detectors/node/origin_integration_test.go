package node_test

import (
	"context"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/bun"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-sdk"
)

// requireArtifactOrigin asserts a package asserts exactly the given artifact.
func requireArtifactOrigin(t *testing.T, g *sdk.Graph, name, version, want string) {
	t.Helper()
	origin := detectors.OriginFrom(requirePackage(t, g, name, version).Metadata)
	if origin.ArtifactURL != want {
		t.Errorf("%s@%s artifact origin = %q, want %q", name, version, origin.ArtifactURL, want)
	}
	if origin.VCSURL != "" {
		t.Errorf("%s@%s also asserted a repository %q", name, version, origin.VCSURL)
	}
}

// requireNoOrigin asserts a package publishes no location at all.
func requireNoOrigin(t *testing.T, g *sdk.Graph, name, version string) {
	t.Helper()
	if origin := detectors.OriginFrom(requirePackage(t, g, name, version).Metadata); !origin.Empty() {
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
