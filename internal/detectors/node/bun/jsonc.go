package bun

import (
	"bytes"
	"errors"
)

// normalizeJSONC removes line comments, block comments, and trailing commas
// while leaving string contents and escape sequences untouched.
func normalizeJSONC(input []byte) ([]byte, error) {
	withoutComments := make([]byte, 0, len(input))
	inString, escaped, lineComment, blockComment := false, false, false, false
	for i := 0; i < len(input); i++ {
		current := input[i]
		next := byte(0)
		if i+1 < len(input) {
			next = input[i+1]
		}
		switch {
		case lineComment:
			if current == '\n' || current == '\r' {
				lineComment = false
				withoutComments = append(withoutComments, current)
			}
		case blockComment:
			if current == '*' && next == '/' {
				blockComment = false
				i++
			} else if current == '\n' || current == '\r' {
				withoutComments = append(withoutComments, current)
			}
		case inString:
			withoutComments = append(withoutComments, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
		case current == '"':
			inString = true
			withoutComments = append(withoutComments, current)
		case current == '/' && next == '/':
			lineComment = true
			i++
		case current == '/' && next == '*':
			blockComment = true
			i++
		default:
			withoutComments = append(withoutComments, current)
		}
	}
	if inString || blockComment {
		return nil, errors.New("unterminated string or block comment")
	}

	out := make([]byte, 0, len(withoutComments))
	inString, escaped = false, false
	for i := 0; i < len(withoutComments); i++ {
		current := withoutComments[i]
		if inString {
			out = append(out, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			out = append(out, current)
			continue
		}
		if current == ',' {
			rest := bytes.TrimLeft(withoutComments[i+1:], " \t\r\n")
			if len(rest) > 0 && (rest[0] == '}' || rest[0] == ']') {
				continue
			}
		}
		out = append(out, current)
	}
	return out, nil
}
