package sbom

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
)

// ErrAmbiguousJSON reports a document whose JSON does not have one unambiguous
// reading: it repeats an object member name, or it contains bytes that are not
// valid UTF-8.
var ErrAmbiguousJSON = errors.New("ambiguous sbom json")

// ErrUnverifiableJSON reports a document Bomly declines to validate because
// checking it would cost more memory than the check is worth.
var ErrUnverifiableJSON = errors.New("unverifiable sbom json")

// maxObjectMembers bounds the widest single JSON object Bomly will validate.
//
// Detecting a repeated name means remembering the names already seen in the
// object still being read, so the check costs memory in proportion to the
// widest object, not to the file. Measured on the pinned toolchain, a 23 MiB
// document holding one two-million-member object retained about 154 MiB --
// roughly seven times its own size, which at the 256 MiB input limit is more
// than a gigabyte and enough to end a CI run.
//
// The bound is on the shape that costs, and nothing real approaches it: the
// widest object either format defines is a component or the document header,
// on the order of twenty members. Components live in an array, and array
// elements need no name tracking. A hundred thousand members in one object is
// therefore four orders of magnitude of headroom and a few megabytes of
// tracking.
//
// Exceeding it fails closed. A document too wide to check is refused rather
// than passed through unchecked, because skipping the check on the largest
// inputs would put the hole exactly where an attacker would put the payload.
const maxObjectMembers = 100_000

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
// The scan is streaming: it builds no parse tree, and its cost is one pass plus
// the names of the object currently open, which maxObjectMembers bounds.
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
			// Classified by what the two readers disagree about, rather than
			// by matching the message. A document the permissive reader also
			// rejects is malformed -- truncated, or not JSON at all -- and
			// saying it "reads two ways" would send the user looking for a
			// repeated member that is not there. Only a document v1 accepts
			// and this one refuses is ambiguous, and the difference between
			// them is exactly the two classes ADR-0039 names.
			//
			// The extra pass is on the error path only.
			if !json.Valid(data) {
				return fmt.Errorf("%w: %w", ErrMalformedJSON, err)
			}
			// The library's message names the offending member and its JSON
			// pointer path, or the byte offset of the bad sequence, which is
			// what makes this actionable: a user can find and fix the spot.
			return fmt.Errorf("%w: %w", ErrAmbiguousJSON, err)
		}
		// Checked as the object grows rather than at its end, so a document
		// designed to exhaust memory is stopped while it is doing it.
		depth := decoder.StackDepth()
		if depth == 0 {
			continue
		}
		// The length counts names and values alike, so an object's member
		// count is half of it. Arrays are not counted: duplicate detection
		// applies to member names, and array elements have none.
		if kind, length := decoder.StackIndex(depth); kind == '{' && length/2 > maxObjectMembers {
			return fmt.Errorf("%w: an object holds more than %d members, which is too wide to check for repeated names",
				ErrUnverifiableJSON, maxObjectMembers)
		}
	}
}
