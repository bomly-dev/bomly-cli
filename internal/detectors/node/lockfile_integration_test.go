package node_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bomly-dev/bomly-cli/internal/detectors/node/npm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/pnpm"
	"github.com/bomly-dev/bomly-cli/internal/detectors/node/yarn"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// ---- helpers ---------------------------------------------------------------

// stableID returns the ID that the lockfile parsers assign: "name@version", or just "name" when version is empty.
func stableID(name, version string) string {
	if version == "" {
		return name
	}
	return fmt.Sprintf("%s@%s", name, version)
}

// requirePackage asserts a package with the given name@version exists in the graph.
func requirePackage(t *testing.T, g *sdk.Graph, name, version string) *sdk.Dependency {
	t.Helper()
	id := stableID(name, version)
	pkg, ok := g.Node(id)
	if !ok {
		t.Fatalf("expected package %s@%s in graph (id=%s); packages present: %v", name, version, id, graphPackageIDs(g))
	}
	return pkg
}

// requireEdge asserts that fromName@fromVersion depends on toName@toVersion.
func requireEdge(t *testing.T, g *sdk.Graph, fromName, fromVersion, toName, toVersion string) {
	t.Helper()
	fromID := stableID(fromName, fromVersion)
	toID := stableID(toName, toVersion)
	deps, err := g.DirectDependencies(fromID)
	if err != nil {
		t.Fatalf("dependencies(%s@%s): %v", fromName, fromVersion, err)
	}
	for _, dep := range deps {
		if dep.ID == toID {
			return
		}
	}
	t.Errorf("expected edge %s@%s → %s@%s", fromName, fromVersion, toName, toVersion)
}

// requireResolvedURL asserts a non-empty ResolvedURL on a named package.
func requireResolvedURL(t *testing.T, g *sdk.Graph, name, version string) {
	t.Helper()
	pkg := requirePackage(t, g, name, version)
	if pkg.ResolvedURL == "" {
		t.Errorf("expected ResolvedURL on %s@%s, got empty string", name, version)
	}
}

// requireDigest asserts that at least one digest with the given algorithm exists.
func requireDigest(t *testing.T, g *sdk.Graph, name, version, algorithm string) {
	t.Helper()
	pkg := requirePackage(t, g, name, version)
	for _, d := range pkg.Digests {
		if d.Algorithm == algorithm {
			return
		}
	}
	t.Errorf("expected %s digest on %s@%s; digests: %+v", algorithm, name, version, pkg.Digests)
}

func requireScope(t *testing.T, g *sdk.Graph, name, version string, scope sdk.Scope) {
	t.Helper()
	pkg := requirePackage(t, g, name, version)
	if got := pkg.PrimaryScope(); got != scope {
		t.Fatalf("expected %s@%s scope %q, got %q", name, version, scope, got)
	}
}

func graphPackageIDs(g *sdk.Graph) []string {
	pkgs := g.Nodes()
	ids := make([]string, len(pkgs))
	for i, p := range pkgs {
		ids[i] = p.ID
	}
	return ids
}

// fixture returns the absolute path to a named fixture directory.
func fixture(name string) string {
	return filepath.Join("testdata", "lockfiles", name)
}

// ---- npm v1 ----------------------------------------------------------------

func TestNPMLockfileV1_Parsing(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v1"))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile(npm-v1): %v", err)
	}
	// root + react + loose-envify + zod = 4 packages
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d: %v", g.Size(), graphPackageIDs(g))
	}
	requirePackage(t, g, "react", "18.2.0")
	requirePackage(t, g, "loose-envify", "1.4.0")
	requirePackage(t, g, "zod", "3.23.0")
}

// ---- npm v2 ----------------------------------------------------------------

func TestNPMLockfileV2_Parsing(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v2"))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile(npm-v2): %v", err)
	}
	// root + express + accepts + typescript = 4 packages
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d: %v", g.Size(), graphPackageIDs(g))
	}
	requirePackage(t, g, "express", "4.18.2")
	requirePackage(t, g, "accepts", "1.3.8")
	requirePackage(t, g, "typescript", "5.3.3")
	requireEdge(t, g, "express", "4.18.2", "accepts", "1.3.8")
}

func TestNPMLockfileV2_Metadata(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v2"))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile(npm-v2): %v", err)
	}
	requireResolvedURL(t, g, "express", "4.18.2")
	requireDigest(t, g, "express", "4.18.2", "sha512")
	// License extracted from lockfile
	pkg := requirePackage(t, g, "express", "4.18.2")
	if len(sdk.DetectionLicenses(pkg)) == 0 {
		t.Errorf("expected license on express@4.18.2")
	}
}

func TestNPMLockfileV2_Scopes(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v2"))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile(npm-v2): %v", err)
	}
	requireScope(t, g, "express", "4.18.2", sdk.ScopeRuntime)
	requireScope(t, g, "accepts", "1.3.8", sdk.ScopeRuntime)
	requireScope(t, g, "typescript", "5.3.3", sdk.ScopeDevelopment)
}

// ---- npm v3 ----------------------------------------------------------------

func TestNPMLockfileV3_Parsing(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v3"))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile(npm-v3): %v", err)
	}
	// root + lodash + jest + jest-circus = 4 packages
	if g.Size() != 4 {
		t.Fatalf("expected 4 packages, got %d: %v", g.Size(), graphPackageIDs(g))
	}
	requirePackage(t, g, "lodash", "4.17.21")
	requirePackage(t, g, "jest", "29.7.0")
	requirePackage(t, g, "jest-circus", "29.7.0")
}

func TestNPMLockfileV3_Metadata(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v3"))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile(npm-v3): %v", err)
	}
	requireResolvedURL(t, g, "lodash", "4.17.21")
	requireDigest(t, g, "lodash", "4.17.21", "sha512")
	pkg := requirePackage(t, g, "lodash", "4.17.21")
	if len(pkg.Licenses) == 0 {
		t.Errorf("expected license on lodash@4.17.21")
	}
	// jest has peerDependencies; NPMPackageMetadata must be populated
	jestPkg := requirePackage(t, g, "jest", "29.7.0")
	meta, ok := jestPkg.Metadata[sdk.MetadataKeyNPM]
	if !ok {
		t.Errorf("expected NPM metadata on jest@29.7.0")
	} else {
		npmMeta, _ := meta.(*sdk.NPMPackageMetadata)
		if npmMeta == nil || len(npmMeta.PeerDependencies) == 0 {
			t.Errorf("expected PeerDependencies in NPM metadata on jest@29.7.0; got %+v", npmMeta)
		}
	}
}

func TestNPMLockfileV3_SingleApplicationRoot(t *testing.T) {
	g, err := resolveLockfileGraph(t, npm.LockfileDetector{}, fixture("npm-v3"))
	if err != nil {
		t.Fatalf("depGraphFromNPMLockfile(npm-v3): %v", err)
	}
	roots := g.Roots()
	if len(roots) != 1 {
		t.Fatalf("expected exactly one root package, got %d: %v", len(roots), graphPackageIDs(g))
	}
	if roots[0].ID != stableID("demo-app", "3.0.0") {
		t.Fatalf("expected npm root %q, got %q", stableID("demo-app", "3.0.0"), roots[0].ID)
	}
}

// ---- pnpm v5 (old format, no importers) ------------------------------------

func TestPNPMLockfileV5_OldFormat(t *testing.T) {
	g, err := resolveLockfileGraph(t, pnpm.LockfileDetector{}, fixture("pnpm-v5"))
	if err != nil {
		t.Fatalf("depGraphFromPNPMLockfile(pnpm-v5): %v", err)
	}
	// root + react + loose-envify + axios + typescript = 5 packages
	if g.Size() != 5 {
		t.Fatalf("expected 5 packages, got %d: %v", g.Size(), graphPackageIDs(g))
	}
	requirePackage(t, g, "react", "18.2.0")
	requirePackage(t, g, "loose-envify", "1.4.0")
	requirePackage(t, g, "axios", "1.6.5")
	requirePackage(t, g, "typescript", "5.3.3")
}

func TestPNPMLockfileV5_RootDependencyEdges(t *testing.T) {
	g, err := resolveLockfileGraph(t, pnpm.LockfileDetector{}, fixture("pnpm-v5"))
	if err != nil {
		t.Fatalf("depGraphFromPNPMLockfile(pnpm-v5): %v", err)
	}
	// Root must depend on the three top-level packages.
	// Root package has name "demo-app" and version "1.0.0" from package.json.
	rootID := stableID("demo-app", "1.0.0")
	rootDeps, err := g.Dependencies(rootID)
	if err != nil {
		t.Fatalf("dependencies(root): %v", err)
	}
	names := make(map[string]bool, len(rootDeps))
	for _, d := range rootDeps {
		names[d.Name] = true
	}
	for _, want := range []string{"react", "axios", "typescript"} {
		if !names[want] {
			t.Errorf("expected root to depend on %s; root deps: %v", want, names)
		}
	}
}

func TestPNPMLockfileV5_Metadata(t *testing.T) {
	g, err := resolveLockfileGraph(t, pnpm.LockfileDetector{}, fixture("pnpm-v5"))
	if err != nil {
		t.Fatalf("depGraphFromPNPMLockfile(pnpm-v5): %v", err)
	}
	requireResolvedURL(t, g, "react", "18.2.0")
	requireDigest(t, g, "react", "18.2.0", "sha512")
}

// ---- pnpm v9 (modern importers format) -------------------------------------

func TestPNPMLockfileV9_Parsing(t *testing.T) {
	g, err := resolveLockfileGraph(t, pnpm.LockfileDetector{}, fixture("pnpm-v9"))
	if err != nil {
		t.Fatalf("depGraphFromPNPMLockfile(pnpm-v9): %v", err)
	}
	// root + react + loose-envify + axios + typescript = 5 packages
	if g.Size() != 5 {
		t.Fatalf("expected 5 packages, got %d: %v", g.Size(), graphPackageIDs(g))
	}
	requirePackage(t, g, "react", "18.2.0")
	requirePackage(t, g, "loose-envify", "1.4.0")
	requirePackage(t, g, "axios", "1.6.5")
	requirePackage(t, g, "typescript", "5.3.3")
	requireEdge(t, g, "react", "18.2.0", "loose-envify", "1.4.0")
}

func TestPNPMLockfileV9_Metadata(t *testing.T) {
	g, err := resolveLockfileGraph(t, pnpm.LockfileDetector{}, fixture("pnpm-v9"))
	if err != nil {
		t.Fatalf("depGraphFromPNPMLockfile(pnpm-v9): %v", err)
	}
	requireResolvedURL(t, g, "react", "18.2.0")
	requireDigest(t, g, "react", "18.2.0", "sha512")
	pkg := requirePackage(t, g, "react", "18.2.0")
	if len(pkg.Licenses) == 0 {
		t.Errorf("expected license on react@18.2.0")
	}
}

func TestPNPMLockfileV9_Scopes(t *testing.T) {
	g, err := resolveLockfileGraph(t, pnpm.LockfileDetector{}, fixture("pnpm-v9"))
	if err != nil {
		t.Fatalf("depGraphFromPNPMLockfile(pnpm-v9): %v", err)
	}
	requireScope(t, g, "react", "18.2.0", sdk.ScopeRuntime)
	requireScope(t, g, "loose-envify", "1.4.0", sdk.ScopeRuntime)
	requireScope(t, g, "axios", "1.6.5", sdk.ScopeRuntime)
	requireScope(t, g, "typescript", "5.3.3", sdk.ScopeDevelopment)
}

// ---- yarn v1 (classic) -----------------------------------------------------

func TestYarnLockfileV1_Parsing(t *testing.T) {
	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, fixture("yarn-v1"))
	if err != nil {
		t.Fatalf("depGraphFromYarnLockfile(yarn-v1): %v", err)
	}
	// root + react + loose-envify + js-tokens + axios = 5 packages
	if g.Size() != 5 {
		t.Fatalf("expected 5 packages, got %d: %v", g.Size(), graphPackageIDs(g))
	}
	requirePackage(t, g, "react", "18.2.0")
	requirePackage(t, g, "loose-envify", "1.4.0")
	requirePackage(t, g, "js-tokens", "4.0.0")
	requirePackage(t, g, "axios", "1.6.5")
	requireEdge(t, g, "react", "18.2.0", "loose-envify", "1.4.0")
}

func TestYarnLockfileV1_Metadata(t *testing.T) {
	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, fixture("yarn-v1"))
	if err != nil {
		t.Fatalf("depGraphFromYarnLockfile(yarn-v1): %v", err)
	}
	requireResolvedURL(t, g, "react", "18.2.0")
	requireDigest(t, g, "react", "18.2.0", "sha512")
}

func TestYarnLockfileV1_SingleApplicationRoot(t *testing.T) {
	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, fixture("yarn-v1"))
	if err != nil {
		t.Fatalf("depGraphFromYarnLockfile(yarn-v1): %v", err)
	}
	roots := g.Roots()
	if len(roots) != 1 {
		t.Fatalf("expected exactly one root package, got %d: %v", len(roots), graphPackageIDs(g))
	}
	if roots[0].ID != stableID("demo-app", "1.0.0") {
		t.Fatalf("expected yarn root %q, got %q", stableID("demo-app", "1.0.0"), roots[0].ID)
	}
}

// ---- yarn Berry (v2+) ------------------------------------------------------

func TestYarnBerry_Parsing(t *testing.T) {
	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, fixture("yarn-berry"))
	if err != nil {
		t.Fatalf("depGraphFromYarnLockfile(yarn-berry): %v", err)
	}
	// root + react + loose-envify + js-tokens + axios = 5 packages
	if g.Size() != 5 {
		t.Fatalf("expected 5 packages, got %d: %v", g.Size(), graphPackageIDs(g))
	}
	requirePackage(t, g, "react", "18.2.0")
	requirePackage(t, g, "loose-envify", "1.4.0")
	requirePackage(t, g, "js-tokens", "4.0.0")
	requirePackage(t, g, "axios", "1.6.5")
	requireEdge(t, g, "react", "18.2.0", "loose-envify", "1.4.0")
}

func TestYarnBerry_MetadataStanzaNotIngested(t *testing.T) {
	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, fixture("yarn-berry"))
	if err != nil {
		t.Fatalf("depGraphFromYarnLockfile(yarn-berry): %v", err)
	}
	// __metadata must never appear as a package
	for _, pkg := range g.Nodes() {
		if pkg.Name == "__metadata" {
			t.Errorf("__metadata was incorrectly ingested as a package node")
		}
	}
}

func TestYarnLockfileScopes(t *testing.T) {
	projectDir := t.TempDir()
	writeTestFile(t, projectDir, "package.json", `{
  "name": "demo-app",
  "version": "1.0.0",
  "dependencies": {
    "react": "^18.2.0"
  },
  "devDependencies": {
    "vitest": "^2.0.0"
  }
}`)
	writeTestFile(t, projectDir, "yarn.lock", `react@^18.2.0:
  version "18.2.0"
  dependencies:
    loose-envify "^1.4.0"

loose-envify@^1.4.0:
  version "1.4.0"

vitest@^2.0.0:
  version "2.0.0"
  dependencies:
    chai "^5.1.0"

chai@^5.1.0:
  version "5.1.0"
`)

	g, err := resolveLockfileGraph(t, yarn.LockfileDetector{}, projectDir)
	if err != nil {
		t.Fatalf("depGraphFromYarnLockfile(scopes): %v", err)
	}
	requireScope(t, g, "react", "18.2.0", sdk.ScopeRuntime)
	requireScope(t, g, "loose-envify", "1.4.0", sdk.ScopeRuntime)
	requireScope(t, g, "vitest", "2.0.0", sdk.ScopeDevelopment)
	requireScope(t, g, "chai", "5.1.0", sdk.ScopeDevelopment)
}

func writeTestFile(t *testing.T, dir string, name string, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func resolveLockfileGraph(t *testing.T, detector sdk.Detector, projectDir string) (*sdk.Graph, error) {
	t.Helper()
	result, err := detector.ResolveGraph(context.Background(), sdk.DetectionRequest{ProjectPath: projectDir})
	if err != nil {
		return nil, err
	}
	return result.Graphs.ConsolidatedGraph()
}
