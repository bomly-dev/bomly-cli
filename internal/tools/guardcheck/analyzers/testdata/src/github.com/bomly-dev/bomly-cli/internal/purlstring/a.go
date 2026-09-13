package purlstring

import (
	"fmt"
	"strings"
)

// A bare literal is data.
const fixture = "pkg:npm/left-pad@1.3.0"

// A prefix check is decomposition, not construction.
func isPURL(s string) bool { return strings.HasPrefix(s, "pkg:") }

func concatLeft(name string) string {
	return "pkg:npm/" + name // want `package URL built from a string literal`
}

func concatRight(scheme, name string) string {
	return scheme + "pkg:" + name // want `package URL built from a string literal`
}

func appended(name string) string {
	s := ""
	s += "pkg:npm/" + name // want `package URL built from a string literal`
	return s
}

func formatted(name, version string) string {
	return fmt.Sprintf("pkg:npm/%s@%s", name, version) // want `package URL built from a string literal`
}

func printed(name string) {
	fmt.Printf("pkg:npm/%s\n", name) // want `package URL built from a string literal`
}

func wrapped(name string) error {
	return fmt.Errorf("resolve %s", "pkg:npm/"+name) // want `package URL built from a string literal`
}

// A literal as a plain argument to a non-printf call is data being passed,
// not a package URL being assembled.
func passed() bool { return isPURL("pkg:npm/left-pad@1.3.0") }
