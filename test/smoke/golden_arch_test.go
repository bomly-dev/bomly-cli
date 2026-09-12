// This file intentionally has no build tag. The architecture a golden was
// generated on is a property of the committed file, not of a scan, so the
// guard below runs in `go test ./...` (make test) rather than only in the
// slow, network-driven `smoke` suite. Catching a host architecture at
// `make test` time is the whole point: the failure this guards against was
// written locally, reviewed green, and only discovered on CI.
//
// The architecture vocabulary lives here too, so the normalizer that erases
// these tokens (helpers_test.go, `smoke`-tagged) and the guard that forbids
// them cannot drift apart -- adding a spelling to hostArchTokens extends
// both at once.

package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// hostArchTokens are the machine-architecture spellings that a scan can pick
// up from whatever machine it ran on, rather than from anything Bomly
// decided. The same machine has several names depending on who is asking:
// dpkg says amd64/arm64/ppc64el, Alpine and RPM say x86_64/aarch64, OCI and
// Go say amd64/arm64/ppc64le.
//
// Delegation check (CLAUDE.md): github.com/containerd/platforms is pinned
// (indirect) and does own the OCI platform vocabulary, including the
// x86_64 -> amd64 and aarch64 -> arm64 aliases. It is deliberately NOT used
// here, for three reasons:
//
//  1. Its vocabulary is OCI's, not dpkg's. Debian spells 64-bit
//     little-endian PowerPC "ppc64el"; OCI spells it "ppc64le". Delegating
//     would silently stop recognising the Debian spelling -- which is the
//     exact spelling this guard exists to catch, since the goldens that
//     carry an architecture are Debian container scans.
//  2. Membership in a library's list is an open set. This list is
//     deliberately closed: an architecture Bomly got *wrong* -- one that is
//     not any real machine -- must stay visible in a golden diff rather than
//     being normalized away.
//  3. Promoting an indirect dependency to a direct one is a dependency
//     addition, which this repo requires discussion for.
//
// So the set is hand-listed, and the guard test below is what keeps the
// hand-listing honest: a spelling missing from here fails review the moment
// it reaches a golden, instead of years later and silently.
var hostArchTokens = []string{
	"mips64le",
	"mips64el",
	"ppc64le",
	"ppc64el",
	"aarch64",
	"riscv64",
	"x86_64",
	"armv7l",
	"armv7",
	"armhf",
	"amd64",
	"arm64",
	"s390x",
	"i686",
	"i386",
}

// hostArchQualifierOnlyTokens are architecture spellings that are only safe
// to match when something else already proves the value is an architecture.
//
// "386" is Go's and OCI's name for 32-bit x86. Scanned loosely across a
// golden it also matches version fragments and digest-adjacent digits, so it
// belongs only in the `arch=` qualifier pattern, where the qualifier name
// settles what the value is.
var hostArchQualifierOnlyTokens = []string{"386"}

// archAlternation builds a regexp alternation from the given tokens, longest
// first. Sorting here rather than relying on the declaration order means a
// token added anywhere in the lists above still wins over any shorter token
// it has as a prefix (Go's regexp alternation is leftmost, not longest).
func archAlternation(tokenLists ...[]string) string {
	var tokens []string
	for _, list := range tokenLists {
		tokens = append(tokens, list...)
	}
	sort.SliceStable(tokens, func(i, j int) bool {
		return len(tokens[i]) > len(tokens[j])
	})
	return strings.Join(tokens, "|")
}

// reHostArchQualifier matches the architecture qualifier a container scan
// reports in a package URL.
//
// A multi-arch image resolves to the runner's own architecture, so this is
// the runner speaking, not Bomly: goldens regenerated on an arm64 laptop and
// compared on an amd64 CI runner differ on every package in the image. The
// suite is here to catch regressions in what Bomly does with an image, and an
// arch that tracks the host is noise in that signal.
var reHostArchQualifier = regexp.MustCompile(
	`([?&]arch=)(?:` + archAlternation(hostArchTokens, hostArchQualifierOnlyTokens) + `)(?:&|$)`)

// reHostArchDpkgPath matches Debian's multiarch suffix in the dpkg
// administrative paths a container scan records as package evidence, e.g.
// "/var/lib/dpkg/info/libc6:amd64.md5sums".
//
// dpkg names a co-installable package's control files "<package>:<arch>.<ext>",
// so the architecture rides into the evidence path even though the PURL
// qualifier it also appears in is already normalized. That gap is what
// issue #445 tripped over: identity was portable, evidence was not, and a
// golden written on arm64 failed only on CI.
//
// The match is anchored to the dpkg directory rather than to ":<arch>."
// anywhere. An architecture that turns up in some other path shape is a case
// nobody has thought about yet, and the guard below should stop it and make
// someone decide, rather than a broad pattern quietly erasing it.
var reHostArchDpkgPath = regexp.MustCompile(
	`(/var/lib/dpkg/info/[^/":]+):(?:` + archAlternation(hostArchTokens) + `)(\.)`)

// reHostArchToken matches any distinctive architecture spelling standing as a
// whole token. It is the guard's catch-all: the two patterns above describe
// the shapes the normalizer knows how to erase, and this one finds the shapes
// it does not.
var reHostArchToken = regexp.MustCompile(
	`(?:^|[^0-9A-Za-z_])(?:` + archAlternation(hostArchTokens) + `)(?:[^0-9A-Za-z_]|$)`)

// forEachJSONString visits every string in a decoded JSON document, including
// object keys, since a key is wire surface too.
func forEachJSONString(value any, visit func(string)) {
	switch typed := value.(type) {
	case string:
		visit(typed)
	case []any:
		for _, element := range typed {
			forEachJSONString(element, visit)
		}
	case map[string]any:
		for key, element := range typed {
			visit(key)
			forEachJSONString(element, visit)
		}
	}
}

// lineOfValue reports the line a decoded string sits on, by asking
// encoding/json to write the value back the way the file would have written
// it. Searching for the raw text would miss exactly the escaped values this
// scan exists to catch.
func lineOfValue(raw []byte, value string) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	index := bytes.Index(raw, encoded)
	if index < 0 {
		return 0
	}
	return lineOf(raw, index)
}

// goldenDir is the single directory holding smoke golden files.
const goldenDir = "testdata/golden"

// TestGoldensCarryNoHostArchitecture fails when a committed golden contains a
// machine architecture.
//
// Not "a foreign architecture" -- any architecture. A golden holding "amd64"
// is not correct just because CI happens to run on amd64; it is the same
// defect that happens to be invisible today, and it becomes visible the next
// time a contributor runs `make smoke ARGS="-update"` on a laptop. The
// portable value is the placeholder the normalizer writes.
func TestGoldensCarryNoHostArchitecture(t *testing.T) {
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("read golden dir %s: %v", goldenDir, err)
	}

	checks := []struct {
		re     *regexp.Regexp
		advice string
	}{
		{
			re: reHostArchDpkgPath,
			advice: "dpkg multiarch evidence path. normalizeMachineDependentString " +
				"(helpers_test.go) rewrites this to :<arch>; the golden predates that " +
				"rule, so rewrite the committed value to match.",
		},
		{
			re: reHostArchQualifier,
			advice: "package URL arch qualifier. normalizeMachineDependentString " +
				"(helpers_test.go) rewrites this to arch=<arch>; the golden predates " +
				"that rule, so rewrite the committed value to match.",
		},
		{
			re: reHostArchToken,
			advice: "architecture in a shape no normalizer covers yet. Decide whether " +
				"it is host-tracking noise (then teach normalizeMachineDependentString " +
				"in helpers_test.go to erase it, and add any missing spelling to " +
				"hostArchTokens) or genuinely part of what the golden asserts (then " +
				"this guard needs an explicit, argued exception).",
		},
	}

	scanned := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".golden.json") {
			continue
		}
		scanned++

		path := filepath.Join(goldenDir, entry.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read golden %s: %v", path, err)
		}

		// Scan the decoded strings, not the file bytes. Go writes "&" as
		// \u0026 inside JSON, and five goldens here carry it that way, so a
		// pattern expecting a literal separator walks straight past
		// "?arch=386\u0026distro=..." -- the very qualifier it exists to
		// find. encoding/json owns that escaping, so it decides what the
		// value is rather than this file learning the escapes.
		var document any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Errorf("%s: golden is not valid JSON: %v", path, err)
			continue
		}

		found := false
		forEachJSONString(document, func(value string) {
			if found {
				return
			}
			for _, check := range checks {
				loc := check.re.FindStringIndex(value)
				if loc == nil {
					continue
				}
				found = true
				t.Errorf("%s:%d: golden carries the host architecture %q\n\n%s\n\n"+
					"A golden is compared on ubuntu-latest (amd64) but is usually written "+
					"on a contributor's machine, so an architecture baked into one fails "+
					"CI for everybody after it merges. See issue #445.",
					path, lineOfValue(raw, value), value[loc[0]:loc[1]], check.advice)
				return
			}
		})
	}

	// A guard that scans nothing passes forever. Fail if the goldens moved.
	if scanned == 0 {
		t.Fatalf("no *.golden.json files found under %s; the guard scanned nothing", goldenDir)
	}
	t.Logf("scanned %d golden files for host architectures", scanned)
}

// lineOf returns the 1-based line number of the byte offset in raw.
func lineOf(raw []byte, offset int) int {
	if offset > len(raw) {
		offset = len(raw)
	}
	return 1 + strings.Count(string(raw[:offset]), "\n")
}

// quoteMatch renders the matched region with a little surrounding context so
// the failure names the actual string rather than only a pattern.
func quoteMatch(raw []byte, loc []int) string {
	start := loc[0] - 40
	if start < 0 {
		start = 0
	}
	end := loc[1] + 40
	if end > len(raw) {
		end = len(raw)
	}
	return fmt.Sprintf("%s  (context: ...%s...)",
		strings.TrimSpace(string(raw[loc[0]:loc[1]])),
		strings.TrimSpace(strings.ReplaceAll(string(raw[start:end]), "\n", " ")))
}
