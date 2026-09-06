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

// maxOpenNameBytes bounds the same thing in bytes.
//
// A count is not a size. A hundred thousand two-kilobyte names sit inside the
// count bound and still weigh two hundred megabytes, so a 194 MiB document --
// legal under the 256 MiB input limit -- passed the count check while driving
// retention to 900 MiB. Names are what the checker holds; bytes are what they
// cost.
//
// Both bounds are kept rather than replacing one with the other: a document
// can be pathological in either direction, and each is cheap.
//
// Sixteen mebibytes is far above anything real. Member names in both formats
// are spec-defined field names of tens of bytes, so a hundred thousand of them
// occupy single-digit megabytes.
//
// Measured, not predicted: the 194 MiB document that used to retain 900 MiB is
// now refused having retained 116 MiB. Estimating from the name bytes alone
// suggested about seventy, so the figure here is the one observed on the
// pinned toolchain -- every earlier comment on this function stated a memory
// property that later measurement contradicted.
//
// One residual is left open deliberately, and it is smaller than it looks. The
// decoder retains a name internally before this code ever sees the token, so a
// single name larger than the bound is held once -- bounded by an input
// already capped at 256 MiB and already resident, so 1x and not a multiplier.
// Closing that would mean sizing the name before the decoder reads it, and
// jsontext exposes no option for it (its Options are duplicate-name,
// invalid-UTF-8, and formatting); the only route left is scanning raw bytes
// for the string's closing quote with escape handling, which mirrors the
// library's tokenizer and is what this project's delegation rule refuses.
//
// What is *not* left open is this code adding a second copy on top of that.
// The span gate below refuses an oversized name before it is read, which is
// where the extra copy came from. Tracked as bomly-dev/bomly-cli#435, which
// asks the larger question about this preflight's shape.
const maxOpenNameBytes = 16 << 20

// openObjectCost is what one open object is costing the duplicate check: the
// member names seen in it so far, and the bytes they occupy. Both are released
// when that object closes.
type openObjectCost struct {
	members   int
	nameBytes int64
}

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
	// A *bytes.Buffer, not a bytes.Reader. The library reads a buffer in
	// place; behind a generic reader it grows a buffer of its own and
	// materializes each token into it, so one very large value -- a long
	// string in an extension member, say -- duplicated most of the document.
	// Measured: a 150 MiB single-string document retained 447 MiB through a
	// reader and nothing at all through a buffer.
	//
	// The count and byte bounds below still matter; they cover member names,
	// which the decoder retains whatever the input is. This covers values,
	// which no bound reaches, by not copying them in the first place.
	//
	// NewBuffer takes ownership of the slice, and the caller reuses it for the
	// real decode straight afterwards -- checked: the scan reads without
	// modifying, the bytes hash the same before and after, and the document
	// still decodes.
	decoder := jsontext.NewDecoder(bytes.NewBuffer(data))
	// What each open object is costing, and the running sums. Kept per depth
	// rather than re-summed from the decoder's stack on every token, which
	// would make the scan cost depth times its length -- and kept in one
	// struct so the two measures are released together when an object closes.
	var open []openObjectCost
	var totalMembers int
	var totalNameBytes int64
	for {
		// Where this token starts, used only as a cheap gate below -- never as
		// the measurement, which is what the previous attempt got wrong.
		start := decoder.InputOffset()
		token, err := decoder.ReadToken()
		if err != nil {
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
		// so they stop counting against either total.
		for len(open) > depth {
			closed := open[len(open)-1]
			totalMembers -= closed.members
			totalNameBytes -= closed.nameBytes
			open = open[:len(open)-1]
		}
		for len(open) < depth {
			open = append(open, openObjectCost{})
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
		totalMembers += members - open[depth-1].members
		open[depth-1].members = members
		// An odd length means the token just read was a member name rather
		// than its value, which is the only token the decoder retains.
		//
		// The name itself is measured, not the span it sat in. Sizing it from
		// input offsets counted the separator and any indentation before it
		// too, which inflated a pretty-printed document by more than six times
		// and would have refused a legal one for whitespace the decoder never
		// holds.
		//
		// But reading the name costs a copy -- measured at a full extra copy
		// of the name, escaped or not -- so a name too large to accept must be
		// refused before it is read, not after. The source span is the gate:
		// it is free, it is never smaller than the name inside it, and a name
		// whose span alone exceeds the whole budget cannot fit however it
		// unescapes. Anything past the gate is small enough that measuring it
		// exactly is cheap.
		//
		// Gate on the span, account with the name. Using the span for both
		// refused legal documents; using the name for both copied hostile
		// ones.
		if length%2 == 1 {
			if span := decoder.InputOffset() - start; span > maxOpenNameBytes {
				return fmt.Errorf("%w: a single object member name spans more than %d bytes, which is more than Bomly will read to check for repeated names",
					ErrUnverifiableJSON, int64(maxOpenNameBytes))
			}
			size := int64(len(token.String()))
			open[depth-1].nameBytes += size
			totalNameBytes += size
		}
		if totalMembers > maxOpenObjectMembers {
			return fmt.Errorf("%w: more than %d object member names are open at once, which is more than Bomly will hold to check for repeated names",
				ErrUnverifiableJSON, maxOpenObjectMembers)
		}
		if totalNameBytes > maxOpenNameBytes {
			return fmt.Errorf("%w: the object member names open at once exceed %d bytes, which is more than Bomly will hold to check for repeated names",
				ErrUnverifiableJSON, int64(maxOpenNameBytes))
		}
	}
}
