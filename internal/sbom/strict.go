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

// maxOpenObjectMembers bounds how many object member names Bomly will hold at
// once while checking a document.
//
// Detecting a repeated name means remembering the names already seen in an
// object, and those names are held until that object closes -- so the cost is
// set by every object open at the same time, not by the file and not by any
// one object. Measured on the pinned toolchain: a 23 MiB document holding one
// two-million-member object retained about 154 MiB, and a 411 MiB document
// nesting three hundred objects of ninety-nine thousand members each retained
// 2.5 GiB, because each level stays open until the last one closes.
//
// Bounding the widest single object caught the first shape and not the second.
// The sum across open objects catches both, because it is the quantity that
// actually costs.
//
// Nothing real approaches it. Both formats keep their components in an array,
// whose elements need no name tracking, so a document being read has a handful
// of objects open at once holding tens of members between them -- the widest
// object either format defines is a component or the document header. A
// hundred thousand names is three orders of magnitude of headroom and a few
// megabytes of tracking.
//
// Exceeding it fails closed. A document too large to check is refused rather
// than passed through unchecked, because skipping the check on the biggest
// inputs would put the hole exactly where an attacker would put the payload.
//
// The bound is a count rather than anything cleverer on purpose: the library
// owns what a duplicate name means, and this owns only how much work Bomly
// will do to find one.
const maxOpenObjectMembers = 100_000

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
	// Members counted per open object, and their running sum. Maintained here
	// rather than re-summed from the decoder's stack on every token, which
	// would make the scan cost depth times its length.
	var openMembers []int
	var total int
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
		// Checked as the document is read rather than at the end, so one
		// built to exhaust memory is stopped while it is doing it.
		depth := decoder.StackDepth()

		// Objects that closed since the previous token release their names,
		// so their members stop counting against the total.
		for len(openMembers) > depth {
			total -= openMembers[len(openMembers)-1]
			openMembers = openMembers[:len(openMembers)-1]
		}
		for len(openMembers) < depth {
			openMembers = append(openMembers, 0)
		}
		if depth == 0 {
			continue
		}

		// The length counts names and values alike, so an object's member
		// count is half of it. Arrays contribute nothing: duplicate detection
		// applies to member names, and array elements have none.
		kind, length := decoder.StackIndex(depth)
		if kind != '{' {
			continue
		}
		members := int(length / 2)
		total += members - openMembers[depth-1]
		openMembers[depth-1] = members
		if total > maxOpenObjectMembers {
			return fmt.Errorf("%w: more than %d object member names are open at once, which is more than Bomly will hold to check for repeated names",
				ErrUnverifiableJSON, maxOpenObjectMembers)
		}
	}
}
