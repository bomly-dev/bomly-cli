package pyreach

import (
	"bufio"
	"io"
	"strings"
)

// scanImports reads Python source and returns the set of top-level
// module names that appear in `import x` and `from x import …`
// statements. Relative imports (`from .foo import bar`,
// `from ..pkg import …`) are skipped — they refer to local app
// packages, never to PyPI distributions. Imports inside string
// literals, comments, and triple-quoted blocks are also skipped.
//
// The scanner is line-oriented and handles:
//
//   - "import x"                       -> {"x"}
//   - "import x.y"                     -> {"x"}
//   - "import x, y, z"                 -> {"x", "y", "z"}
//   - "import x as a, y as b"          -> {"x", "y"}
//   - "from x import y"                -> {"x"}
//   - "from x.y import z"              -> {"x"}
//   - "from . import foo"              -> {} (relative)
//   - "from .foo import bar"           -> {} (relative)
//   - "    import x"                   -> {"x"} (indented; conditional / function-local)
//   - "import x  # noqa"               -> {"x"} (trailing comment)
//   - "import x; import y"             -> {"x"} (semicolons not split — rare in real code)
//
// What it deliberately skips:
//
//   - Multi-line imports inside parens (`from x import (\n  a,\n  b\n)`).
//     Only the first line is scanned; the analyzer doesn't need the
//     imported symbols anyway, just the source module.
//   - String-literal imports passed to importlib.import_module(...).
//     Those are the entire reason Tier-3 "unreachable" is not "safe".
//   - Imports inside triple-quoted strings or docstrings — the scanner
//     keeps a trivial state machine to skip those. The scanner does
//     NOT attempt to handle every edge case of Python's lexical
//     grammar; false positives (an import-looking line inside a
//     comment block) are acceptable since the BFS through the dep
//     graph then maps them to a no-op.
func scanImports(r io.Reader) (map[string]struct{}, error) {
	imports := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
	// Allow up to 1 MB per line — Python source rarely has long
	// lines but pathological generated code can.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1<<20)
	inTripleQuote := false
	tripleQuoteStr := ""
	for scanner.Scan() {
		line := scanner.Text()
		stripped := stripComment(line)
		// Triple-quoted block tracking. Cheap and approximate — we
		// only check whether a """ or ''' appears on the line,
		// without tracking column position. Imports buried inside
		// docstrings are vanishingly rare.
		if inTripleQuote {
			if strings.Contains(line, tripleQuoteStr) {
				inTripleQuote = false
			}
			continue
		}
		// Detect opening triple-quote on this line.
		if i := indexAny(line, `"""`, `'''`); i >= 0 {
			marker := line[i : i+3]
			rest := line[i+3:]
			// If the closing triple-quote appears on the same line,
			// it's a single-line docstring — not a block. Ignore it
			// unless it's the only content; in either case, do not
			// flip into block mode.
			if !strings.Contains(rest, marker) {
				inTripleQuote = true
				tripleQuoteStr = marker
				// fall through and still scan the prefix before
				// the triple quote, in case the line is something
				// like `import x  # docstring follows """`.
			}
		}
		trimmed := strings.TrimSpace(stripped)
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "import "):
			for _, mod := range parseImportTargets(trimmed[len("import "):]) {
				if mod != "" {
					imports[mod] = struct{}{}
				}
			}
		case strings.HasPrefix(trimmed, "from "):
			mod := parseFromTarget(trimmed[len("from "):])
			if mod != "" {
				imports[mod] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return imports, nil
}

// stripComment returns line with any trailing "# …" comment removed.
// It is intentionally naive — it does not track string literals — so
// "x = '#'  # comment" becomes "x = '". This is fine for the import
// scanner because real `import` and `from` lines never contain string
// literals before the comment marker.
func stripComment(line string) string {
	if i := strings.Index(line, "#"); i >= 0 {
		return line[:i]
	}
	return line
}

// parseImportTargets splits the operand of an `import` statement into
// the top-level module names being imported. Handles aliases ("as x")
// and comma-separated lists.
func parseImportTargets(operand string) []string {
	parts := strings.Split(operand, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Drop "as <alias>" suffix.
		if i := strings.Index(p, " as "); i >= 0 {
			p = p[:i]
		}
		p = strings.TrimSpace(p)
		// Take the top-level segment.
		if i := strings.Index(p, "."); i >= 0 {
			p = p[:i]
		}
		// Skip relative-import dots and empty.
		if p == "" || strings.HasPrefix(p, ".") {
			continue
		}
		// Reject anything that looks non-identifier (semicolons, colons).
		if !isLikelyIdentifier(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// parseFromTarget extracts the source-module of a `from x import …`
// statement, returning the top-level segment. Returns "" for relative
// imports (`from .` / `from ..`) and for malformed input.
func parseFromTarget(operand string) string {
	operand = strings.TrimSpace(operand)
	if operand == "" {
		return ""
	}
	// Find the " import " separator. We look for the keyword
	// surrounded by whitespace on both sides to avoid false matches
	// like "from importlib import …".
	idx := strings.Index(operand, " import ")
	if idx < 0 {
		return ""
	}
	src := strings.TrimSpace(operand[:idx])
	// Relative imports start with one or more dots.
	if src == "" || strings.HasPrefix(src, ".") {
		return ""
	}
	if i := strings.Index(src, "."); i >= 0 {
		src = src[:i]
	}
	if !isLikelyIdentifier(src) {
		return ""
	}
	return src
}

// isLikelyIdentifier reports whether s is a plausible Python identifier
// (letters, digits, underscore, with a non-digit first character). The
// scanner uses it as a sanity check on what it parsed; non-identifier
// junk is dropped silently.
func isLikelyIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
			// always ok
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// indexAny returns the first index where any of the provided
// substrings is found, or -1 when none of them appear. Used to
// approximate triple-quote detection without scanning twice.
func indexAny(line string, opts ...string) int {
	first := -1
	for _, opt := range opts {
		if i := strings.Index(line, opt); i >= 0 {
			if first < 0 || i < first {
				first = i
			}
		}
	}
	return first
}
