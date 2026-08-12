package jvmreach

import (
	"bufio"
	"io"
	"strings"
)

// scanImports reads JVM source (.java / .kt / .kts / .scala / .groovy)
// and returns the set of fully-qualified imports. Each entry is a
// dotted FQN — the import path as written by the user, before any
// wildcard or selector expansion.
//
// Supported syntactic forms:
//
//	Java:
//	  import com.foo.Bar;
//	  import com.foo.*;
//	  import static com.foo.Bar.baz;
//
//	Kotlin (.kt, .kts):
//	  import com.foo.Bar
//	  import com.foo.*
//	  import com.foo.Bar as B
//
//	Scala:
//	  import com.foo.Bar
//	  import com.foo.{Bar, Baz}
//	  import com.foo.{Bar => B, _}
//	  import com.foo._
//
//	Groovy:
//	  same shape as Java, optional semicolon
//
// The scanner is line-oriented. It tracks /* ... */ block comments
// (but not nested) and skips // line comments. Triple-quoted Kotlin
// raw strings and Scala interpolators are not modeled — false
// positives there are harmless because the analyzer's downstream
// prefix mapping won't have an entry for a string-literal FQN. The
// scanner stops paying attention to imports after the first line
// that does not look like an import, a comment, or whitespace; this
// matches the JLS / Kotlin / Scala rule that imports come at the
// top of the file.
//
// Returned FQNs are the "source path" only (everything before the
// last segment for Java/Kotlin "import foo.bar.Baz;", or everything
// inside `from x import ...`-like Scala selectors). The caller
// (resolveArtifacts) decides what prefix to match.
func scanImports(r io.Reader) (map[string]struct{}, error) {
	imports := make(map[string]struct{})
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1<<20)
	inBlockComment := false
	// sawNonImport tracks whether we've passed the import header of
	// the file. After the first non-comment, non-blank, non-import
	// line we stop looking — saves work on big source files.
	sawNonImport := false
	for scanner.Scan() {
		raw := scanner.Text()
		// Strip block comments straddling the line. We do not track
		// strings; an import-looking substring inside a string
		// literal at the top of a file is vanishingly rare in real
		// JVM code.
		line, stillInBlock := stripBlockComment(raw, inBlockComment)
		inBlockComment = stillInBlock
		// Strip a trailing line-comment.
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "package "):
			// package declaration; keep scanning.
		case strings.HasPrefix(trimmed, "import "):
			for _, fqn := range parseImportLine(trimmed[len("import "):]) {
				if fqn != "" {
					imports[fqn] = struct{}{}
				}
			}
		default:
			// First substantive non-import line. Stop scanning.
			sawNonImport = true
		}
		if sawNonImport {
			break
		}
	}
	// Drain the rest of the file so the scanner.Err() check below
	// is meaningful for early-truncated readers.
	for scanner.Scan() {
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return imports, nil
}

// stripBlockComment removes any /* ... */ block-comment content from
// line. When inBlock is true on entry, the prefix of line is treated
// as already inside a block. Returns the trimmed line and the new
// "in-block" state.
func stripBlockComment(line string, inBlock bool) (string, bool) {
	out := ""
	i := 0
	for i < len(line) {
		if inBlock {
			end := strings.Index(line[i:], "*/")
			if end < 0 {
				return out, true
			}
			i += end + 2
			inBlock = false
			continue
		}
		start := strings.Index(line[i:], "/*")
		if start < 0 {
			out += line[i:]
			break
		}
		out += line[i : i+start]
		i += start + 2
		inBlock = true
	}
	return out, inBlock
}

// parseImportLine takes the operand of an `import` statement (after
// the keyword) and returns the set of source-side FQNs it implies.
//
// For Java: "static com.foo.Bar.baz;" -> "com.foo.Bar" (drop the
// member). For Kotlin: "com.foo.Bar as B" -> "com.foo.Bar". For
// Scala: "com.foo.{Bar, Baz}" -> {"com.foo.Bar", "com.foo.Baz"};
// "com.foo._" -> "com.foo"; "com.foo.{Bar => B, _}" -> "com.foo.Bar".
//
// Returned FQNs include the import's full source path so the prefix
// resolver can match the most specific prefix possible.
func parseImportLine(operand string) []string {
	operand = strings.TrimSpace(operand)
	operand = strings.TrimSuffix(operand, ";")
	operand = strings.TrimSpace(operand)
	if operand == "" {
		return nil
	}
	// Java "import static com.foo.Bar.baz" — drop the leading
	// "static " keyword and the trailing member identifier (last
	// segment after the package).
	staticImport := false
	if strings.HasPrefix(operand, "static ") {
		operand = strings.TrimSpace(operand[len("static "):])
		staticImport = true
	}
	// Kotlin "import com.foo.Bar as B" — drop the alias.
	if i := strings.Index(operand, " as "); i >= 0 {
		operand = operand[:i]
	}
	operand = strings.TrimSpace(operand)
	if operand == "" {
		return nil
	}
	// Scala selector: "com.foo.{A, B => C, _}"
	if i := strings.Index(operand, "{"); i >= 0 {
		j := strings.LastIndex(operand, "}")
		if j < 0 || j < i {
			return nil
		}
		prefix := strings.TrimSpace(operand[:i])
		prefix = strings.TrimSuffix(prefix, ".")
		inside := operand[i+1 : j]
		parts := strings.Split(inside, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" || p == "_" {
				if prefix != "" {
					out = appendUnique(out, prefix)
				}
				continue
			}
			// "A => B" — keep A.
			if k := strings.Index(p, "=>"); k >= 0 {
				p = strings.TrimSpace(p[:k])
			}
			if !isIdentLike(p) {
				continue
			}
			fqn := prefix
			if fqn != "" {
				fqn += "."
			}
			fqn += p
			out = appendUnique(out, fqn)
		}
		return out
	}
	// Trailing wildcard `.*` or `._` => keep everything before the
	// wildcard (Scala uses `_`, Java/Kotlin use `*`).
	for _, suffix := range []string{".*", "._"} {
		if strings.HasSuffix(operand, suffix) {
			return []string{strings.TrimSuffix(operand, suffix)}
		}
	}
	// Plain `import a.b.c.Class` form. Keep the full path. For
	// `import static`, also strip the trailing member identifier so
	// the prefix match sees the type, not the field.
	if staticImport {
		if i := strings.LastIndex(operand, "."); i >= 0 {
			operand = operand[:i]
		}
	}
	if !isDotIdent(operand) {
		return nil
	}
	return []string{operand}
}

// isIdentLike reports whether s looks like a single Java/Kotlin/Scala
// identifier (letters, digits, underscore, plus '$' which is legal
// for inner-class references).
func isIdentLike(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '_', r == '$':
			// ok
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// isDotIdent reports whether s is a dot-separated chain of
// identifiers. Used to drop garbage that doesn't look like a real
// import path.
func isDotIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if !isIdentLike(part) {
			return false
		}
	}
	return true
}

func appendUnique(out []string, v string) []string {
	for _, x := range out {
		if x == v {
			return out
		}
	}
	return append(out, v)
}
