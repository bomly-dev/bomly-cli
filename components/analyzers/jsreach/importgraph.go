package jsreach

import (
	"encoding/json"
	"fmt"
	"strings"
)

// metafile is the subset of the esbuild metafile structure we consume.
// The full schema (https://esbuild.github.io/api/#metafile) carries
// quite a bit more information; we only care about per-input imports
// flagged as external because PackagesExternal forces every bare
// specifier into that bucket.
type metafile struct {
	Inputs map[string]metafileInput `json:"inputs"`
}

type metafileInput struct {
	Imports []metafileImport `json:"imports"`
}

type metafileImport struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	External bool   `json:"external"`
}

// extractImportedPackages parses an esbuild metafile and returns the
// set of npm package names that were imported anywhere in the project's
// reachable source tree. Subpath imports are normalized to the owning
// package name so `@scope/pkg/util` maps to `@scope/pkg`.
//
// Imports that aren't bare specifiers (relative paths, absolute paths,
// data URLs, the `node:` builtin scheme, asset suffixes esbuild made
// virtual) are skipped.
func extractImportedPackages(metafileJSON string) (map[string]struct{}, int, error) {
	var meta metafile
	if err := json.Unmarshal([]byte(metafileJSON), &meta); err != nil {
		return nil, 0, fmt.Errorf("parse esbuild metafile: %w", err)
	}
	imports := make(map[string]struct{})
	sourceFiles := 0
	for inputPath, input := range meta.Inputs {
		// Filter out node_modules sources from the source-file count;
		// they shouldn't appear when PackagesExternal is set, but
		// being defensive here keeps the count meaningful for logs.
		if isNodeModulesPath(inputPath) {
			continue
		}
		sourceFiles++
		for _, imp := range input.Imports {
			pkg := normalizeBareSpecifier(imp.Path)
			if pkg == "" {
				continue
			}
			imports[pkg] = struct{}{}
		}
	}
	return imports, sourceFiles, nil
}

// normalizeBareSpecifier converts an esbuild import path into the npm
// package name it points at, or returns "" when the path is not a
// bare specifier we can attribute to a package.
//
// Examples:
//
//	"react"                    -> "react"
//	"react/jsx-runtime"        -> "react"
//	"@scope/pkg"               -> "@scope/pkg"
//	"@scope/pkg/util"          -> "@scope/pkg"
//	"./relative/path"          -> "" (skipped: relative)
//	"/abs/path"                -> "" (skipped: absolute)
//	"node:fs"                  -> "" (skipped: builtin)
//	"file://..."               -> "" (skipped: URL scheme)
func normalizeBareSpecifier(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	// Skip relative and absolute filesystem paths.
	if strings.HasPrefix(path, ".") || strings.HasPrefix(path, "/") {
		return ""
	}
	// Skip URL-scheme imports including the "node:" builtin scheme.
	if i := strings.Index(path, ":"); i > 0 {
		// Anything with a colon before a slash is a scheme — bare
		// specifiers don't legally contain colons.
		return ""
	}
	if strings.HasPrefix(path, "@") {
		// Scoped package: keep the first two segments
		// (@scope/name); drop any subpath.
		segments := strings.SplitN(path, "/", 3)
		if len(segments) < 2 {
			return ""
		}
		return segments[0] + "/" + segments[1]
	}
	// Unscoped: keep the first segment.
	if i := strings.Index(path, "/"); i >= 0 {
		return path[:i]
	}
	return path
}

// isNodeModulesPath reports whether a metafile input key points inside
// node_modules. esbuild emits paths with forward slashes regardless of
// host OS so we do not need to normalize separators.
func isNodeModulesPath(path string) bool {
	return strings.Contains(path, "/node_modules/") || strings.HasPrefix(path, "node_modules/")
}
