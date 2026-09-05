package sbom

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
)

// ErrAmbiguousJSON reports a document whose JSON does not have one unambiguous
// reading: it repeats an object member name, or it contains bytes that are not
// valid UTF-8.
var ErrAmbiguousJSON = errors.New("ambiguous sbom json")

// requireUnambiguousJSON rejects a document that could be read two ways
// (ADR-0039).
//
// Under encoding/json's v1 semantics a repeated object name still parses, and
// which value wins depends on the Go type being decoded into -- replacement
// for a scalar field, merging for a struct or map. Two consumers reading the
// same document into different shapes can therefore read two different license
// or package URL values out of it. For a tool whose whole job is to say what is
// in someone else's dependency tree, that is a smuggling vector, not a
// curiosity. Invalid UTF-8 is the same class: v1 silently substitutes U+FFFD,
// so the bytes a consumer sees are not the bytes the document carried.
//
// This validates rather than decodes, and the distinction is deliberate. The
// guarantee ADR-0039 makes is exactly these two ambiguity classes, and no
// others. Decoding through encoding/json/v2 would also change field matching
// from case-insensitive to case-sensitive and alter how the format libraries'
// own unmarshalers are invoked -- behavior changes nobody validated and the ADR
// explicitly does not claim. A separate strict pass over the same bytes buys
// the stated guarantee and nothing else.
//
// The scan is streaming, so a 256 MiB document costs one pass and constant
// memory rather than a second full parse tree.
func requireUnambiguousJSON(data []byte) error {
	// jsontext's defaults are the rule being enforced: duplicate object names
	// and invalid UTF-8 are both refused unless a caller opts out. The
	// standard library owns what "the same name twice" means -- including
	// escaped spellings of one name, which a byte comparison here would miss.
	decoder := jsontext.NewDecoder(bytes.NewReader(data))
	for {
		if _, err := decoder.ReadToken(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			// The library's message names the offending member and its JSON
			// pointer path, or the byte offset of the bad sequence, which is
			// what makes this actionable: a user can find and fix the spot.
			return fmt.Errorf("%w: %w", ErrAmbiguousJSON, err)
		}
	}
}
