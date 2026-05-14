package jsreach

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// discoverEntryPoints inspects projectDir/package.json and returns the
// absolute paths of every entry point worth walking from. The order is
// deterministic so analyzer logs are stable across runs.
//
// Sources of entry points, in the order they're collected:
//
//  1. "main"    — Node's CJS entry; required by older modules.
//  2. "module"  — ESM entry preferred by bundlers when present.
//  3. "browser" — entry for browser bundlers; we accept the string
//     form and ignore the redirect-map form.
//  4. "exports" — modern conditional-export map. We pull every leaf
//     string we find so subpath exports are exercised.
//  5. "bin"     — CLI entry points. Accepts both the string form
//     ("bin": "./cli.js") and the object map form
//     ("bin": {"name": "./cli.js"}).
//
// If none of those produced an entry, fall back to Node's implicit
// "index.js" / "index.mjs" / "index.ts" lookup at the project root so
// projects that omit "main" still get walked.
//
// Files are deduplicated, filtered to those that actually exist on
// disk, and returned as absolute paths so esbuild's metafile keys
// match the analyzer's bookkeeping.
func discoverEntryPoints(projectDir string) ([]string, error) {
	pkgPath := filepath.Join(projectDir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("package.json not found at %s", pkgPath)
		}
		return nil, fmt.Errorf("read %s: %w", pkgPath, err)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", pkgPath, err)
	}

	var candidates []string
	candidates = appendIfNonEmpty(candidates, pkg.Main)
	candidates = appendIfNonEmpty(candidates, pkg.Module)
	candidates = append(candidates, browserEntryStrings(pkg.Browser)...)
	candidates = append(candidates, exportsEntryStrings(pkg.Exports)...)
	candidates = append(candidates, binEntryStrings(pkg.Bin)...)

	if len(candidates) == 0 {
		candidates = append(candidates, defaultIndexCandidates()...)
	}

	seen := make(map[string]struct{}, len(candidates))
	resolved := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		abs := candidate
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(projectDir, candidate)
		}
		clean := filepath.Clean(abs)
		if _, ok := seen[clean]; ok {
			continue
		}
		info, err := os.Stat(clean)
		if err != nil || info.IsDir() {
			continue
		}
		seen[clean] = struct{}{}
		resolved = append(resolved, clean)
	}

	if len(resolved) == 0 {
		return nil, fmt.Errorf("no resolvable entry points in %s", pkgPath)
	}
	return resolved, nil
}

// packageJSON captures the subset of package.json we need to derive
// entry points. Every field is optional; we tolerate any shape.
type packageJSON struct {
	Main    string          `json:"main"`
	Module  string          `json:"module"`
	Browser json.RawMessage `json:"browser"`
	Exports json.RawMessage `json:"exports"`
	Bin     json.RawMessage `json:"bin"`
}

// browserEntryStrings accepts either a scalar string or an object
// (path-redirect map). The scalar form is itself a real entry; the
// object form's values are not "entry points" in the Node sense — they
// are path overrides — so we ignore that shape.
func browserEntryStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		return []string{s}
	}
	return nil
}

// exportsEntryStrings recursively walks the exports field and
// collects every leaf string. Conditional exports look like:
//
//	"exports": {
//	    ".": {"import": "./esm/index.js", "require": "./cjs/index.js"},
//	    "./util": "./util.js"
//	}
//
// We don't try to enforce the condition matching algorithm — we want
// every import path in case any of them is real. esbuild will reject
// the ones that don't actually exist when it walks them.
func exportsEntryStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	walkJSONStrings(raw, func(s string) {
		out = append(out, s)
	})
	return out
}

// binEntryStrings handles the two shapes:
//
//	"bin": "./cli.js"
//	"bin": {"my-cli": "./cli.js"}
func binEntryStrings(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		return []string{s}
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err == nil {
		out := make([]string, 0, len(m))
		for _, value := range m {
			if value != "" {
				out = append(out, value)
			}
		}
		return out
	}
	return nil
}

// walkJSONStrings emits every string scalar inside raw.
func walkJSONStrings(raw json.RawMessage, emit func(string)) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil && asString != "" {
		emit(asString)
		return
	}
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err == nil {
		for _, child := range asArray {
			walkJSONStrings(child, emit)
		}
		return
	}
	var asObject map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asObject); err == nil {
		for _, child := range asObject {
			walkJSONStrings(child, emit)
		}
	}
}

// defaultIndexCandidates lists the implicit entry locations Node and
// most bundlers fall back to when no package.json field declares one.
//
// The first set is Node's official resolution algorithm — `index.*` at
// the project root and under `src/`. The second set covers the common
// Node-app conventions (`app.js`, `server.js`, `main.js`) where the
// package.json typically wires them in via "scripts": {"start": "node
// app.js"} rather than the "main" field. Parsing the scripts object is
// fragile (start scripts can be arbitrary commands), so we instead
// look for the file directly. False positives are harmless: if a
// project happens to ship an unrelated `app.js` at the root, the
// import graph it produces is still a reachable subset of the project.
//
// We return relative paths; the caller resolves them against
// projectDir and filters by existence.
func defaultIndexCandidates() []string {
	return []string{
		"index.js",
		"index.mjs",
		"index.cjs",
		"index.ts",
		"index.tsx",
		filepath.Join("src", "index.js"),
		filepath.Join("src", "index.mjs"),
		filepath.Join("src", "index.ts"),
		filepath.Join("src", "index.tsx"),
		// Common Node-app conventions wired via scripts rather than main.
		"app.js",
		"app.ts",
		"server.js",
		"server.ts",
		"main.js",
		"main.ts",
	}
}

func appendIfNonEmpty(values []string, candidate string) []string {
	if candidate == "" {
		return values
	}
	return append(values, candidate)
}
