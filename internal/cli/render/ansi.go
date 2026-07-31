// Package render owns CLI presentation primitives: ANSI styling, the startup logo,
// and SBOM output spec parsing. Higher-level scan / diff / explain text rendering
// remains in the cli package for now (it depends on many cli-internal helpers);
// extracting it is tracked as follow-up work.
package render

import "strings"

// ANSI escape sequences reused across cli text rendering and the interactive TUI.
const (
	Reset   = "\x1b[0m"
	Black   = "\x1b[30m"
	Red     = "\x1b[31m"
	Green   = "\x1b[32m"
	Yellow  = "\x1b[33m"
	Blue    = "\x1b[34m"
	Magenta = "\x1b[35m"
	Purple  = "\x1b[38;5;141m"
	Orange  = "\x1b[38;5;208m"
	Cyan    = "\x1b[36m"
	White   = "\x1b[37m"
	Gray    = "\x1b[90m"
	Bold    = "\x1b[1m"
	Dim     = "\x1b[2m"

	BgBlue    = "\x1b[44m"
	BgCyan    = "\x1b[44m"
	BgBrand   = "\x1b[48;2;232;155;92m"
	BgNeutral = "\x1b[100m"
	BgGreen   = "\x1b[42m"
	BgRed     = "\x1b[41m"
	BgYellow  = "\x1b[43m"
	BgMagenta = "\x1b[100m"
)

// Wrap returns value bracketed by the given color/style and a reset.
func Wrap(value, color string) string {
	if value == "" || color == "" {
		return value
	}
	return color + value + Reset
}

// Style applies one or more ANSI codes to value.
func Style(value string, codes ...string) string {
	if value == "" || len(codes) == 0 {
		return value
	}
	return strings.Join(codes, "") + value + Reset
}

// StripANSI removes any CSI escape sequences from value.
func StripANSI(value string) string {
	var out strings.Builder
	inEscape := false
	for idx := 0; idx < len(value); idx++ {
		ch := value[idx]
		if inEscape {
			if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') {
				inEscape = false
			}
			continue
		}
		if ch == 0x1b && idx+1 < len(value) && value[idx+1] == '[' {
			inEscape = true
			idx++
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}

// SanitizeUntrusted makes repository-controlled text safe to print inside a
// styled line. Values that reach the report from scanned content — config
// values, version pins, file names, subprocess error text — can contain
// terminal control sequences, and a report line is written straight to a TTY:
// an embedded CSI or OSC sequence could clear the screen, move the cursor, or
// forge output that looks like Bomly's own.
//
// Every ESC-introduced sequence is dropped (CSI "ESC [", OSC "ESC ]" up to its
// BEL or ST terminator, and single-character escapes), along with any remaining
// C0 control byte and DEL. Whitespace runs are then folded to single spaces so
// the result is a single line.
func SanitizeUntrusted(value string) string {
	var out strings.Builder
	out.Grow(len(value))
	for idx := 0; idx < len(value); idx++ {
		ch := value[idx]
		if ch == 0x1b {
			idx = skipEscapeSequence(value, idx)
			continue
		}
		// C0 controls and DEL, with whitespace kept for the fold below.
		if ch < 0x20 || ch == 0x7f {
			if ch == '\t' || ch == '\n' || ch == '\r' {
				out.WriteByte(' ')
			}
			continue
		}
		out.WriteByte(ch)
	}
	return strings.Join(strings.Fields(out.String()), " ")
}

// skipEscapeSequence returns the index of the last byte of the escape sequence
// starting at the ESC byte value[idx], so the caller's loop resumes after it.
func skipEscapeSequence(value string, idx int) int {
	if idx+1 >= len(value) {
		return idx
	}
	switch next := value[idx+1]; {
	case next == '[': // CSI: parameters and intermediates, then a final byte.
		for cursor := idx + 2; cursor < len(value); cursor++ {
			if value[cursor] >= 0x40 && value[cursor] <= 0x7e {
				return cursor
			}
		}
		return len(value)
	case next == ']' || next == 'P' || next == 'X' || next == '^' || next == '_':
		// OSC / DCS / SOS / PM / APC: a string terminated by BEL or ST (ESC \).
		for cursor := idx + 2; cursor < len(value); cursor++ {
			if value[cursor] == 0x07 {
				return cursor
			}
			if value[cursor] == 0x1b && cursor+1 < len(value) && value[cursor+1] == '\\' {
				return cursor + 1
			}
		}
		return len(value)
	case next >= 0x20 && next <= 0x2f:
		// Intermediate bytes (e.g. ESC ( B charset designators), then a final byte.
		cursor := idx + 1
		for cursor < len(value) && value[cursor] >= 0x20 && value[cursor] <= 0x2f {
			cursor++
		}
		if cursor < len(value) {
			return cursor
		}
		return len(value)
	default: // Two-character escape (ESC c, ESC 7, ...): drop the pair.
		return idx + 1
	}
}
