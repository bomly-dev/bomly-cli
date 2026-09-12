package detectors_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// internalRoot is the tree these guards police.
const internalRoot = "../../internal"

// The modules no package under internal/ may reach for directly. They are
// named once, here, so the forbidding rule and the exemption that lets a guard
// spell the module share one string: a typo in either would otherwise open a
// hole quietly, in the direction of passing.
const (
	spdxModule       = "github.com/github/go-spdx"
	packageURLModule = "github.com/package-url/packageurl-go"
	// The deprecated fork. sdk.ParsePackageURL used to return its type; a
	// file reaching for it now is reaching around purlkit for an answer
	// purlkit already has.
	anchorePackageURLModule = "github.com/anchore/packageurl-go"
)

// The rules below, named so the registry can say which one forbids what.
const (
	ruleSPDX       = "TestNoDirectSPDXExpressionUse"
	rulePackageURL = "TestNoDirectPackageURLUse"
)

// knownRules is every rule in this file that scans for forbidden modules.
var knownRules = []string{ruleSPDX, rulePackageURL}

// forbiddenModules maps each rule to the modules it forbids. No package under
// internal/ may reach for any of them directly.
//
// One declaration, read from three directions: each rule takes its list from
// here, guardFiles grants exemptions against these modules, and the
// entitlement test validates against them. Spelled separately, they drifted
// immediately -- the constants landed and the package-URL rule kept scanning
// its own duplicated literals, so a rule could scan one module while an
// entitlement excused another.
//
// Keyed by rule rather than carrying an owner string per module, because an
// owner is a field somebody can mistype. A module filed under
// "TestNoDirectPurlUse" would belong to no rule, be scanned by nothing, and
// still satisfy an entitlement -- a hole in exactly the direction that passes.
// TestRuleRegistryCoversEveryRule pins both halves: every key is a rule that
// runs, and every rule that runs is a key.
//
// What this still does not prove is that each named rule exists and executes.
// Go cannot ask that without depending on test ordering, which breaks under
// -run. Deleting a rule while leaving its key here is the remaining gap, and
// it is a visible edit to this file rather than a silent widening.
var forbiddenModules = map[string][]string{
	ruleSPDX:       {spdxModule},
	rulePackageURL: {packageURLModule, anchorePackageURLModule},
}

// modulesForRule returns the modules one rule forbids.
//
// It fails rather than returning nothing. A rule scanning an empty list
// reports no offenders however many there are, which reads exactly like a rule
// that passed.
func modulesForRule(t *testing.T, rule string) []string {
	t.Helper()
	modules, ok := forbiddenModules[rule]
	if !ok || len(modules) == 0 {
		t.Fatalf("rule %q forbids nothing; it would scan for no modules and report success", rule)
	}
	return modules
}

// isForbidden reports whether any rule forbids the module.
func isForbidden(module string) bool {
	for _, modules := range forbiddenModules {
		for _, forbidden := range modules {
			if forbidden == module {
				return true
			}
		}
	}
	return false
}

// The registry is keyed by rule name, so a typo in a key files modules under a
// rule nothing runs, and they go unscanned while every other check still
// passes. Both directions are pinned: a key that is not a rule, and a rule
// that is not a key.
func TestRuleRegistryCoversEveryRule(t *testing.T) {
	known := make(map[string]struct{}, len(knownRules))
	for _, rule := range knownRules {
		known[rule] = struct{}{}
	}
	for rule := range forbiddenModules {
		if _, ok := known[rule]; !ok {
			t.Errorf("forbiddenModules files modules under %q, which is not a rule in this file; "+
				"they are scanned by nothing", rule)
		}
	}
	for _, rule := range knownRules {
		if len(forbiddenModules[rule]) == 0 {
			t.Errorf("rule %q forbids no modules; it scans for nothing and reports success", rule)
		}
	}
}

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
	for _, module := range modulesForRule(t, ruleSPDX) {
		if offenders := filesNamingModule(t, module); len(offenders) > 0 {
			t.Fatalf("these files reference %s directly; the parser panics on malformed input, "+
				"so go through bomly-sdk/spdxkit instead: %v", module, offenders)
		}
	}
}

// guardFiles maps a guard file to the modules it is entitled to name. Its job
// is to forbid those modules, so it has to spell them; naming a module in a
// rule that bans it is the opposite of reaching for it.
//
// Entitled to *those* modules, not to all of them. An exemption keyed by path
// alone let this file's neighbour name go-spdx and the deprecated fork with no
// rule reporting it -- it needed to spell one module and was excused from
// every check. The value side is what keeps a guard's licence narrow.
//
// The key is an explicit canonical path, for two reasons learned the hard way.
// Matching a name instead exempted every guards_test.go under internal/, so a
// second guard file anywhere could name a forbidden module unnoticed. And
// exempting only this one file made the guards flag each other the moment a
// second one existed: internal/output grew its own presentation-layer guard,
// which must name packageurl-go to forbid it, and this rule reported it.
//
// Adding a guard therefore costs one line here, on purpose. That is the point:
// a new exemption should be a deliberate edit somebody reviews, not a pattern
// that silently widens.
var guardFiles = map[string][]string{
	// This file states every module rule, so it names every module.
	filepath.Clean(filepath.Join(internalRoot, "detectors", "guards_test.go")): {
		spdxModule, packageURLModule, anchorePackageURLModule,
	},
	// The presentation-layer guard forbids exactly one module, so it may
	// name exactly that one.
	filepath.Clean(filepath.Join(internalRoot, "output", "registry_lookup_guard_test.go")): {
		packageURLModule,
	},
}

// guardMayName reports whether path is a guard file entitled to name module.
//
// By path, and per module. Exempting anything named guards_test.go was the
// first bug here: a second guard file in any package could then name a
// forbidden module unreported. Exempting a path from every check was the
// second: a guard that must spell one module was excused from the rules about
// the others.
func guardMayName(path, module string) bool {
	for _, allowed := range guardFiles[filepath.Clean(path)] {
		if allowed == module {
			return true
		}
	}
	return false
}

// importsModule reports whether the Go file at path imports module, or a
// package beneath it.
//
// An entitlement covers naming a module, never importing it. Those are
// different acts: a guard spells the module in a string so it can forbid it,
// while an import is the hazard the rule exists to prevent. Without this, an
// entitled guard could import the module outright and go unreported -- its own
// package guard skips _test.go files, so nothing else was looking.
//
// go/parser decides what counts as an import. A textual scan cannot: it reads
// the module path inside this file's own const block, or a comment, as an
// import, and the whole point here is telling those apart.
func importsModule(t *testing.T, path, module string) bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, spec := range file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		// A subpackage counts: go-spdx's parser is reached as
		// github.com/github/go-spdx/v2/spdxexp, not by the module path.
		if imported == module || strings.HasPrefix(imported, module+"/") {
			return true
		}
	}
	return false
}

// filesNamingModule returns every Go file under internal/ -- test files
// included -- whose text names the module path. Tests count because a test
// reaching a library directly proves the hazard is still reachable, and a test
// is where the temptation lives. The only files skipped are the guards
// entitled to name this particular module, per guardFiles -- and only while
// they merely name it. An entitled file that imports the module is reported
// like any other.
//
// Every module rule runs through here, so a mistake in the exemption opens all
// of them at once, which is why the exemption is narrow in both directions: by
// path rather than by file name, and per module rather than wholesale. If a
// guard file is moved or renamed, its exemption stops matching and the guard
// reports it -- failing in the direction that gets noticed.
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
		if guardMayName(path, module) && !importsModule(t, path, module) {
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
	var offenders []string
	for _, module := range modulesForRule(t, rulePackageURL) {
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

// The exemption is keyed by path, scoped to a module, and granted only against
// a module some rule here actually forbids. Every part of that has been wrong
// before: matching the basename hid a forbidden import in a second
// guards_test.go, exempting only one file made two guards report each other,
// exempting a path from every rule let a guard name two modules it has no
// business naming, and asking whether the file merely contained the module
// string made the last check pass on its own constant declaration.
func TestGuardExemptionIsByPathAndPerModule(t *testing.T) {
	for path, modules := range guardFiles {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("guard file %q does not exist; a dead exemption is a rule nobody is applying", path)
		}
		for _, module := range modules {
			if !guardMayName(path, module) {
				t.Errorf("guard file %q is not entitled to %s by its own predicate", path, module)
			}
			// An entitlement for a module no rule forbids is a licence
			// to import something nothing bans. This used to ask
			// whether the file's text contained the module, which this
			// file satisfies by declaring the constant -- the check
			// passed no matter which modules were actually enforced.
			if !isForbidden(module) {
				t.Errorf("guard file %q is entitled to name %s, which no rule here forbids; "+
					"drop the entitlement or add the rule", path, module)
			}
			// Naming is the licence; importing is the hazard.
			if importsModule(t, path, module) {
				t.Errorf("guard file %q imports %s -- an entitlement covers naming a module, not importing it",
					path, module)
			}
		}
	}

	// A guard is excused from the rule it states, not from the others. This
	// is the hole the path-only exemption left: internal/output's guard
	// forbids packageurl-go, and was thereby excused from the go-spdx and
	// deprecated-fork rules too.
	outputGuard := filepath.Join(internalRoot, "output", "registry_lookup_guard_test.go")
	for _, module := range []string{spdxModule, anchorePackageURLModule} {
		if guardMayName(outputGuard, module) {
			t.Errorf("%q may name %s, a module its rule says nothing about", outputGuard, module)
		}
	}

	// A file named like a guard, in a package that has none, must not be
	// exempt from anything -- whether or not it exists today.
	impostor := filepath.Join(internalRoot, "sbom", "guards_test.go")
	for _, module := range []string{spdxModule, packageURLModule, anchorePackageURLModule} {
		if guardMayName(impostor, module) {
			t.Errorf("%q may name %s for being called guards_test.go rather than for being a guard",
				impostor, module)
		}
	}
}

// The predicate behind that last assertion, pinned in both directions on
// fixtures rather than on the repository, so it keeps its meaning when the
// real guard files change.
func TestNamingAModuleIsNotImportingIt(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return path
	}

	// What a guard file does: spells the module so it can forbid it.
	named := write("named.go", "package p\n\n// "+packageURLModule+" is forbidden.\nconst m = \""+packageURLModule+"\"\n")
	if importsModule(t, named, packageURLModule) {
		t.Errorf("naming %s in a const and a comment reads as importing it; the entitlement would never apply",
			packageURLModule)
	}

	// What the rule exists to catch, including behind a blank identifier.
	imported := write("imported.go", "package p\n\nimport _ \""+packageURLModule+"\"\n")
	if !importsModule(t, imported, packageURLModule) {
		t.Errorf("a blank import of %s is not seen as one", packageURLModule)
	}

	// The module path is not always the import path: go-spdx's parser lives
	// under /v2/spdxexp, so a prefix match is what the rule needs.
	sub := write("sub.go", "package p\n\nimport \""+spdxModule+"/v2/spdxexp\"\n\nvar _ = spdxexp.ValidateLicenses\n")
	if !importsModule(t, sub, spdxModule) {
		t.Errorf("a subpackage import of %s is not seen as reaching the module", spdxModule)
	}

	// A different module that merely starts with the same path must not.
	other := write("other.go", "package p\n\nimport \""+packageURLModule+"-extras\"\n")
	if importsModule(t, other, packageURLModule) {
		t.Errorf("%s-extras reads as %s; the prefix match is missing its separator",
			packageURLModule, packageURLModule)
	}
}
