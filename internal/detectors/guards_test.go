package detectors_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// internalRoot is the tree these guards police.
const internalRoot = "../../internal"

// walkInternalGo visits every non-test Go file under internal/.
func walkInternalGo(t *testing.T, visit func(path, body string)) {
	t.Helper()
	err := filepath.Walk(internalRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		visit(path, string(body))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// A hand-written "is it already there?" check before an insert is how a dozen
// detectors independently decided what happens to a duplicate record. Node
// insertion goes through the shared helper so the behavior is decided once and
// a detector written later inherits it.
//
// The helper is detectorkit.EnsureNode in the SDK now; nothing under internal/
// is exempt, because there is no longer a local copy for a detector to reach
// for instead.
func TestNodeInsertionGoesThroughTheSharedHelper(t *testing.T) {
	// A lookup on the graph followed by an insert, which is the shape that
	// silently discards the duplicate.
	// Any receiver and any identifier, not the one variable name this rule was
	// first written against. The regex used to spell the lookup as
	// `.Node(node.ID)`, so internal/sbom's `.Node(packageID)` walked straight
	// past it and silently discarded a duplicate component's assertions for as
	// long as the guard has existed. A guard that only catches the shape you
	// already fixed is not a guard.
	lookupThenAdd := regexp.MustCompile(`(?s)\.Node\([A-Za-z_][\w.]*\).{0,200}?\.AddNode\(`)

	var offenders []string
	walkInternalGo(t, func(path, body string) {
		if lookupThenAdd.MatchString(body) {
			offenders = append(offenders, path)
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("these files check for an existing node and insert by hand, which drops the duplicate's origin; "+
			"call detectorkit.EnsureNode instead: %v", offenders)
	}
}

// Raw manifest values -- local paths, credentialed private-registry URLs --
// must be unreachable from the export layer. Export reads Origin.Normalized(),
// which is validated end to end; ResolvedURL is evidence, never output. This
// is the structural answer to "could export accidentally leak the raw value":
// it cannot name it.
func TestExportNeverReadsResolvedURL(t *testing.T) {
	root := filepath.Join(internalRoot, "sbom")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var offenders []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if strings.Contains(string(body), "ResolvedURL") {
			offenders = append(offenders, path)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("the export layer references ResolvedURL; it must read Origin.Normalized() only: %v", offenders)
	}
}

// The SPDX expression parser panics on some malformed input, and license
// strings arrive from lockfiles and registry APIs that a repository controls,
// so no package here may call it directly.
//
// The guard used to live in internal/licenseexpr, which wrapped the parser and
// caught its panics. That package is gone: bomly-sdk/spdxkit owns expression
// handling now, panic guard included, so the rule is no longer "route through
// the local wrapper" but "do not import the parser at all". Written as a
// module-path check rather than an import-list scan of one package, because
// the point is that nothing under internal/ reaches the parser by any route.
func TestNoDirectSPDXExpressionUse(t *testing.T) {
	const spdxModule = "github.com/github/go-spdx"

	if offenders := filesNamingModule(t, spdxModule); len(offenders) > 0 {
		t.Fatalf("these files reference %s directly; the parser panics on malformed input, "+
			"so go through bomly-sdk/spdxkit instead: %v", spdxModule, offenders)
	}
}

// guardFiles are the files whose job is to forbid a module, so they are the
// files that have to spell it. Exempting them is not a loophole -- naming a
// module in a rule that bans it is the opposite of reaching for it.
//
// An explicit set of canonical paths, for two reasons learned the hard way.
// Matching a name instead exempted every guards_test.go under internal/, so a
// second guard file anywhere could name a forbidden module unnoticed. And
// exempting only this one file made the guards flag each other the moment a
// second one existed: internal/output grew its own presentation-layer guard,
// which must name packageurl-go to forbid it, and this rule reported it.
//
// Adding a guard therefore costs one line here, on purpose. That is the point:
// a new exemption should be a deliberate edit somebody reviews, not a pattern
// that silently widens.
var guardFiles = map[string]struct{}{
	filepath.Clean(filepath.Join(internalRoot, "detectors", "guards_test.go")):             {},
	filepath.Clean(filepath.Join(internalRoot, "output", "registry_lookup_guard_test.go")): {},
}

// isGuardFile reports whether a path is one of the guard files above.
//
// By path. Exempting anything named guards_test.go was the earlier bug: it
// meant a second guard file in any package could name a forbidden module and
// no rule would report it.
func isGuardFile(path string) bool {
	_, ok := guardFiles[filepath.Clean(path)]
	return ok
}

// filesNamingModule returns every Go file under internal/ -- test files
// included -- whose text names the module path. Tests count because a test
// reaching a library directly proves the hazard is still reachable, and a test
// is where the temptation lives. This file is the one exemption: it has to
// spell out the module paths it forbids.
//
// One file, not one file name. Matching the basename exempted every
// guards_test.go under internal/, so a second guard file in any other package
// could name a forbidden module and neither rule would report it -- and both
// rules run through here, so the hole opened both at once. If this file ever
// moves, the exemption stops matching and the guard reports itself, which is
// the right direction to fail.
func filesNamingModule(t *testing.T, module string) []string {
	t.Helper()
	var offenders []string
	err := filepath.Walk(internalRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if isGuardFile(path) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(body), module) {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", internalRoot, err)
	}
	return offenders
}

// Package URLs are a grammar with escaping rules, per-type case rules, a
// qualifier vocabulary, and a canonical rendering -- all of which belong to
// the specification, not to this repository. bomly-sdk/purlkit is the one
// place that speaks to the library that implements them (ADR-0038), so
// everything here asks purlkit and nothing here parses on its own.
//
// The rule is written as "do not name the library" rather than "route through
// the wrapper" because there are two libraries to name: the official
// package-url/packageurl-go, and the anchore fork the SDK used to expose and
// no longer does. Both still arrive as indirect dependencies through other
// tools, so both stay importable and neither may be imported.
func TestNoDirectPackageURLUse(t *testing.T) {
	modules := []string{
		"github.com/package-url/packageurl-go",
		// The deprecated fork. sdk.ParsePackageURL used to return its type;
		// a file reaching for it now is reaching around purlkit for an
		// answer purlkit already has.
		"github.com/anchore/packageurl-go",
	}
	var offenders []string
	for _, module := range modules {
		for _, path := range filesNamingModule(t, module) {
			offenders = append(offenders, path+" names "+module)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("these files reference a package-url library directly; PURL syntax, escaping, and "+
			"canonical form are bomly-sdk/purlkit's to decide: %v", offenders)
	}
}

// A package URL pasted together from a "pkg:" literal and some escaping is the
// shape that produced a real defect: the SBOM export built its synthesized
// project root with url.PathEscape, which leaves '@' alone, so a project named
// "app@2" exported an identity that read back as "app" at version "2". The
// separators are the specification's to escape, so the parts go into
// purlkit.Build and the string comes out.
//
// Only shipped code is policed. A test fixture spelling out a package URL is
// data, and a test that builds a hundred of them in a loop is doing the same
// thing a table would.
func TestPURLStringsAreBuiltByTheKit(t *testing.T) {
	// A "pkg:..." literal on either side of a concatenation, or as a format
	// string. A prefix or suffix check against the literal is decomposition,
	// not construction, and is not what this rule is about.
	construction := regexp.MustCompile(`"pkg:[^"]*"\s*\+|\+\s*"pkg:|printf\("pkg:|Printf\("pkg:|Sprintf\("pkg:`)

	var offenders []string
	walkInternalGo(t, func(path, body string) {
		if construction.MatchString(body) {
			offenders = append(offenders, path)
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("these files build a package URL by string concatenation; call purlkit.Build so the "+
			"specification's escaping applies to the separators too: %v", offenders)
	}
}

// Strict JSON parsing is an ingest defense, not a global policy. ADR-0039
// scopes it to untrusted documents -- SBOM ingest today -- and explicitly
// leaves the plugin wire alone: enabled plugins are trusted native processes,
// so `bomly.plugin.v1`'s compatibility contract is frozen fixtures, not
// strictness, and tightening it is a protocol decision that needs its own ADR.
//
// The hazard is drift, not intent. Nobody would set out to make the plugin
// wire strict; someone reaches for the stricter reader because it is the one
// they just used, and the wire tightens by accident. So the strict packages
// are confined to the one package that owns ingest, and a new caller has to
// change this rule on purpose.
func TestStrictJSONStaysInSBOMIngest(t *testing.T) {
	strictPackages := []string{`"encoding/json/v2"`, `"encoding/json/jsontext"`}

	// internal/sbom owns document ingest and is where the gate lives.
	const owner = "internal/sbom"

	var offenders []string
	walkInternalGo(t, func(path, body string) {
		if strings.Contains(filepath.ToSlash(path), owner+"/") {
			return
		}
		for _, pkg := range strictPackages {
			if strings.Contains(body, pkg) {
				offenders = append(offenders, path+" imports "+pkg)
			}
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("strict JSON parsing is scoped to SBOM ingest (ADR-0039); "+
			"the plugin wire and the rest of internal/ keep v1 decoding: %v", offenders)
	}
}

// A detection result that carries graphs but skips Attributed ships locations
// with nothing to join reachability evidence to: the module root is the join
// key ADR-0037 defines, and a detector that forgets it leaves every site
// unattributed for the whole pipeline. Wrapping the returned literal is one
// line, which is exactly the kind of rule that gets forgotten, so it is
// enforced here rather than remembered.
//
// The two exemptions are recorded, not implied: neither source has a module
// root to name. See the comments those files carry.
func TestDetectionResultsCarryingGraphsAreAttributed(t *testing.T) {
	exempt := map[string]string{
		"../../internal/detectors/sbom/detector.go":          "an ingested document's packages were resolved elsewhere",
		"../../internal/detectors/githubactions/detector.go": "a workflow file is not a module",
	}
	// A returned result literal that names Graphs. The wrapped form reads
	// "return detectors.Attributed(sdk.DetectionResult{", so it never matches.
	returnsGraphs := regexp.MustCompile(`return sdk\.DetectionResult\{[^}]*Graphs`)

	var offenders []string
	walkInternalGo(t, func(path, body string) {
		if !strings.Contains(filepath.ToSlash(path), "internal/detectors/") {
			return
		}
		if _, ok := exempt[filepath.ToSlash(path)]; ok {
			return
		}
		if returnsGraphs.MatchString(body) {
			offenders = append(offenders, path)
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("these detectors return graphs without recording which module root produced each site; "+
			"wrap the result in detectors.Attributed: %v", offenders)
	}
}

// The exemption is a set of paths, and a file is not exempt for being named
// like a guard. Both halves have been wrong here before: matching the basename
// hid a forbidden import in a second guards_test.go, and exempting only one
// file made two guards report each other.
func TestGuardExemptionIsByPathNotByName(t *testing.T) {
	for path := range guardFiles {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("guard file %q does not exist; a dead exemption is a rule nobody is applying", path)
		}
		if !isGuardFile(path) {
			t.Errorf("guard file %q is not recognized by its own predicate", path)
		}
	}
	// A file named like a guard, in a package that has none, must not be
	// exempt -- whether or not it exists today.
	if impostor := filepath.Join(internalRoot, "sbom", "guards_test.go"); isGuardFile(impostor) {
		t.Errorf("%q is exempt for being named guards_test.go rather than for being a guard", impostor)
	}
}
