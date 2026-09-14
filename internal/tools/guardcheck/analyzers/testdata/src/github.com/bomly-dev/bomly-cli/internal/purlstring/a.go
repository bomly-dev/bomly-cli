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
	return "pkg:npm/" + name // want `package URL built from a "pkg:" string`
}

func concatRight(scheme, name string) string {
	return scheme + "pkg:" + name // want `package URL built from a "pkg:" string`
}

func appended(name string) string {
	s := ""
	s += "pkg:npm/" + name // want `package URL built from a "pkg:" string`
	return s
}

func formatted(name, version string) string {
	return fmt.Sprintf("pkg:npm/%s@%s", name, version) // want `package URL built from a "pkg:" string`
}

func printed(name string) {
	fmt.Printf("pkg:npm/%s\n", name) // want `package URL built from a "pkg:" string`
}

func wrapped(name string) error {
	return fmt.Errorf("resolve %s", "pkg:npm/"+name) // want `package URL built from a "pkg:" string`
}

// A literal as a plain argument to a non-printf call is data being passed,
// not a package URL being assembled.
func passed() bool { return isPURL("pkg:npm/left-pad@1.3.0") }

// A named constant is folded by the type checker: the prefix is still there.
const scheme = "pkg:"

func viaConst(name string) string {
	return scheme + "npm/" + name // want `package URL built from a "pkg:" string`
}

// A constant expression is folded too, and assembling it is itself a
// concatenation of the prefix.
const npmPrefix = scheme + "npm/" // want `package URL built from a "pkg:" string`

func viaConstExpr(name string) string {
	return fmt.Sprintf("%s%s", npmPrefix, name) // want `package URL built from a "pkg:" string`
}

// A local variable defined from the prefix carries it to the concatenation.
func viaLocal(name string) string {
	prefix := "pkg:npm/"
	return prefix + name // want `package URL built from a "pkg:" string`
}

// Appending to a variable that started as the prefix.
func viaAppend(name string) string {
	value := "pkg:npm/"
	value += name // want `package URL built from a "pkg:" string`
	return value
}

// A chain of definitions keeps the taint.
func viaChain(name string) string {
	a := "pkg:"
	b := a
	return b + name // want `package URL built from a "pkg:" string`
}

// A local that merely holds a package URL for a prefix check is data.
func localData(s string) bool {
	known := "pkg:npm/left-pad@1.3.0"
	return s == known || strings.HasPrefix(s, scheme)
}
