package python

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bomly-dev/bomly-cli/internal/detectors"
	"github.com/bomly-dev/bomly-cli/sdk"
)

// poetryLockPackageHeader matches the `[[package]]` start of a
// package block in poetry.lock or Cargo.lock-style TOML.
var poetryLockPackageHeader = regexp.MustCompile(`^\[\[\s*package\s*\]\]\s*$`)

// tomlNameLine matches `name = "foo"` within a TOML block. The
// quotes can be single or double; we accept whitespace either side.
var tomlNameLine = regexp.MustCompile(`^\s*name\s*=\s*["']([^"']+)["']\s*$`)

// poetryLockPositions returns name -> SourcePosition for every
// `[[package]]` block in a poetry.lock file. The position points at
// the `name = "..."` line.
func poetryLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	collectTOMLPackagePositions(path, relPath, out, poetryLockPackageHeader)
	return out
}

// uvLockPositions reuses the same TOML positional shape — uv.lock is
// also a TOML file with `[[package]]` blocks.
func uvLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	collectTOMLPackagePositions(path, relPath, out, poetryLockPackageHeader)
	return out
}

// pdmLockPositions also uses the same TOML shape.
func pdmLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	collectTOMLPackagePositions(path, relPath, out, poetryLockPackageHeader)
	return out
}

// collectTOMLPackagePositions walks a TOML file looking for blocks
// that start with the supplied header regex (e.g. `[[package]]`). For
// each block it records the line of the `name = "..."` field.
func collectTOMLPackagePositions(path, relPath string, out map[string]*sdk.SourcePosition, header *regexp.Regexp) {
	inBlock := false
	scanLinesQuiet(path, func(line int, text string) {
		switch {
		case header.MatchString(text):
			inBlock = true
		case inBlock:
			matches := tomlNameLine.FindStringSubmatch(text)
			if matches != nil {
				name := normalizePythonName(strings.TrimSpace(matches[1]))
				if name == "" {
					return
				}
				if _, exists := out[name]; exists {
					return
				}
				out[name] = &sdk.SourcePosition{File: relPath, Line: line}
				inBlock = false
				return
			}
			// A new top-level table starts a fresh non-package block.
			if strings.HasPrefix(strings.TrimSpace(text), "[") && !strings.HasPrefix(strings.TrimSpace(text), "[[package]]") {
				inBlock = false
			}
		}
	})
}

// pipfileLockPositions returns positions for Pipfile.lock (JSON).
// Pipfile.lock has two top-level objects ("default" and "develop"),
// each a map of package_name -> {version, ...}. We scan line-by-line
// looking for `"<name>": {` patterns inside either block.
//
// The implementation is approximate: it does not parse JSON
// positionally. False positives are unlikely because the `"name": {`
// pattern is rare outside package keys.
var pipfileLockPackageKey = regexp.MustCompile(`^\s*"([^"]+)"\s*:\s*\{\s*$`)

func pipfileLockPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	// Only count keys after we see "default": { or "develop": {.
	inSection := false
	scanLinesQuiet(path, func(line int, text string) {
		trimmed := strings.TrimSpace(text)
		switch trimmed {
		case `"default": {`, `"develop": {`, `"default" : {`, `"develop" : {`:
			inSection = true
			return
		}
		if !inSection {
			return
		}
		matches := pipfileLockPackageKey.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		raw := matches[1]
		if raw == "" || raw == "_meta" {
			return
		}
		name := normalizePythonName(raw)
		if _, exists := out[name]; exists {
			return
		}
		out[name] = &sdk.SourcePosition{File: relPath, Line: line}
	})
	return out
}

// pipfilePositions returns positions for the Pipfile (TOML, not the
// lockfile). Pipfile uses `[packages]` and `[dev-packages]` sections
// listing `name = "..."` declarations.
var pipfileSectionHeader = regexp.MustCompile(`^\[(packages|dev-packages)\]\s*$`)
var pipfileNameLine = regexp.MustCompile(`^\s*([A-Za-z0-9._-]+)\s*=`)

func pipfilePositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	inSection := false
	scanLinesQuiet(path, func(line int, text string) {
		trimmed := strings.TrimSpace(text)
		if pipfileSectionHeader.MatchString(trimmed) {
			inSection = true
			return
		}
		if strings.HasPrefix(trimmed, "[") && !pipfileSectionHeader.MatchString(trimmed) {
			inSection = false
			return
		}
		if !inSection || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			return
		}
		matches := pipfileNameLine.FindStringSubmatch(text)
		if matches == nil {
			return
		}
		name := normalizePythonName(matches[1])
		if name == "" {
			return
		}
		if _, exists := out[name]; exists {
			return
		}
		out[name] = &sdk.SourcePosition{File: relPath, Line: line}
	})
	return out
}

// pyprojectTomlPositions returns positions for pyproject.toml.
// Handles three flavors:
//
//   - [project] dependencies / optional-dependencies lists (PEP 621)
//   - [tool.poetry.dependencies] table (Poetry)
//   - [tool.uv.dependencies] / [tool.pdm.dependencies] tables
//
// Each declaration appears on its own line in some recognizable
// form. We extract a per-section name -> line index.
var (
	pyprojectProjectDepHeader = regexp.MustCompile(`^\[project\]\s*$`)
	pyprojectDepKeyTable      = regexp.MustCompile(`^\[(?:tool\.poetry\.dependencies|tool\.poetry\.dev-dependencies|tool\.poetry\.group\.[^\]]+\.dependencies|tool\.uv\.dependencies|tool\.pdm\.dev-dependencies|tool\.pdm)\]\s*$`)
	pyprojectDepListKey       = regexp.MustCompile(`^\s*(?:dependencies|optional-dependencies)\s*=`)
	pyprojectDepListItem      = regexp.MustCompile(`^\s*["']([A-Za-z0-9._-]+)`)
	pyprojectDepTableEntry    = regexp.MustCompile(`^\s*([A-Za-z0-9._-]+)\s*=`)
)

func pyprojectTomlPositions(path, relPath string) map[string]*sdk.SourcePosition {
	out := make(map[string]*sdk.SourcePosition)
	state := pyprojectStateNone
	scanLinesQuiet(path, func(line int, text string) {
		trimmed := strings.TrimSpace(text)
		switch {
		case pyprojectProjectDepHeader.MatchString(trimmed):
			state = pyprojectStateProject
			return
		case pyprojectDepKeyTable.MatchString(trimmed):
			state = pyprojectStateDepTable
			return
		case strings.HasPrefix(trimmed, "["):
			state = pyprojectStateNone
			return
		}
		switch state {
		case pyprojectStateProject:
			// "dependencies = [...]" or "optional-dependencies = {..}"
			if pyprojectDepListKey.MatchString(text) {
				state = pyprojectStateProjectList
				return
			}
		case pyprojectStateProjectList:
			if strings.HasPrefix(trimmed, "]") {
				state = pyprojectStateProject
				return
			}
			matches := pyprojectDepListItem.FindStringSubmatch(text)
			if matches == nil {
				return
			}
			name := normalizePythonName(matches[1])
			if name == "" {
				return
			}
			if _, exists := out[name]; exists {
				return
			}
			out[name] = &sdk.SourcePosition{File: relPath, Line: line}
		case pyprojectStateDepTable:
			matches := pyprojectDepTableEntry.FindStringSubmatch(text)
			if matches == nil {
				return
			}
			name := matches[1]
			if name == "python" {
				// Poetry uses `python = "^3.8"` as a constraint, not a dep.
				return
			}
			normalized := normalizePythonName(name)
			if normalized == "" {
				return
			}
			if _, exists := out[normalized]; exists {
				return
			}
			out[normalized] = &sdk.SourcePosition{File: relPath, Line: line}
		}
	})
	return out
}

type pyprojectState int

const (
	pyprojectStateNone pyprojectState = iota
	pyprojectStateProject
	pyprojectStateProjectList
	pyprojectStateDepTable
)

// attachLoosePythonPositions invokes every Python-side extractor and
// attaches positions to graph packages. The existing requirements*.txt
// pass in attachDeclaredPositions runs separately.
func attachLoosePythonPositions(g *sdk.Graph, projectPath string) {
	if g == nil || projectPath == "" {
		return
	}
	merged := make(map[string]*sdk.SourcePosition)
	files := []struct {
		name    string
		extract func(string, string) map[string]*sdk.SourcePosition
	}{
		{"poetry.lock", poetryLockPositions},
		{"uv.lock", uvLockPositions},
		{"pdm.lock", pdmLockPositions},
		{"Pipfile.lock", pipfileLockPositions},
		{"Pipfile", pipfilePositions},
		{"pyproject.toml", pyprojectTomlPositions},
	}
	for _, f := range files {
		full := filepath.Join(projectPath, f.name)
		got := f.extract(full, f.name)
		for k, v := range got {
			if _, exists := merged[k]; exists {
				continue // earlier-listed file wins (lockfile > manifest)
			}
			merged[k] = v
		}
	}
	if len(merged) == 0 {
		return
	}
	for _, pkg := range g.Nodes() {
		if pkg == nil {
			continue
		}
		key := normalizePythonName(pkg.Name)
		pos, ok := merged[key]
		if !ok {
			continue
		}
		duplicate := false
		for _, loc := range pkg.Locations {
			if loc.RealPath == pos.File {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		pkg.Locations = append(pkg.Locations, sdk.PackageLocation{
			RealPath:   pos.File,
			AccessPath: pos.File,
			Position:   pos,
		})
	}
}

// scanLinesQuiet wraps detectors.ScanLines and swallows errors,
// since position attachment is always best-effort.
func scanLinesQuiet(path string, fn func(line int, text string)) {
	_ = detectors.ScanLines(path, fn)
}
