// Package analyzers holds the house rules that are about the shape of code
// rather than about a resolved name: a lookup followed by an insert, a
// package URL pasted together from a literal, a detection result built
// without its attribution, a name the export layer may not mention even
// inside a string. No linter expresses those, so each is a go/analysis
// analyzer run by the guardcheck command through go vet.
//
// Each analyzer keys on where the decision is made and asks the type checker
// which package a method, literal or constant belongs to, so an alias, a
// wrapper, a hoisted constant or a local type with the same method names
// does not evade it (ADR-0044 rules 1 and 6). Each has a fixture under
// testdata with a `// want` comment on every forbidden shape and a passing
// shape beside it; the fixture runs in `make test`, which is the rule "a
// guard must be able to fail" made permanent rather than proved once by
// hand.
//
// Only shipped code is policed: files ending in _test.go are skipped, because
// a test spells the forbidden shape on purpose. Generated files are not
// skipped: a generator's output is shipped code.
//
// gocritic's ruleguard DSL was considered for these rules and declined. The
// two-statement lookup-then-insert shape is awkward in a single-expression
// DSL, the rule file would need the go-ruleguard/dsl module, and the
// fixture-driven proof above is native to analysistest, not to a DSL run
// inside golangci-lint.
package analyzers

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

const (
	// modelPath owns the graph; pluginPath owns the detection result. Since
	// bomly-sdk v0.13.0 those are two packages, and the analyzers match on the
	// import path rather than on a package name, so each rule names the path
	// that declares the type it is about.
	modelPath  = "github.com/bomly-dev/bomly-sdk/model"
	pluginPath = "github.com/bomly-dev/bomly-sdk/plugin"
	// detectorsPath is where Attributed and Unattributed are defined.
	detectorsPath = "github.com/bomly-dev/bomly-cli/internal/detectors"
)

// shippedFiles returns the package's files that are not test files.
func shippedFiles(pass *analysis.Pass) []*ast.File {
	var files []*ast.File
	for _, file := range pass.Files {
		if strings.HasSuffix(pass.Fset.File(file.Pos()).Name(), "_test.go") {
			continue
		}
		files = append(files, file)
	}
	return files
}

// isNamed reports whether t is the named type pkgPath.name, looking through
// pointers.
func isNamed(t types.Type, pkgPath, name string) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Pkg().Path() == pkgPath && named.Obj().Name() == name
}

// methodOn reports whether fn is a method named name on the named type
// pkgPath.typeName.
func methodOn(fn *types.Func, pkgPath, typeName, name string) bool {
	if fn == nil || fn.Name() != name {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	return isNamed(sig.Recv().Type(), pkgPath, typeName)
}

// funcIn reports whether fn is the package-level function pkgPath.name.
func funcIn(fn *types.Func, pkgPath, name string) bool {
	if fn == nil || fn.Name() != name || fn.Pkg() == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	return ok && sig.Recv() == nil && fn.Pkg().Path() == pkgPath
}

// variableOf returns the variable an expression names, or nil when it is not
// a plain identifier bound to one.
func variableOf(pass *analysis.Pass, expr ast.Expr) *types.Var {
	ident, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return nil
	}
	obj := pass.TypesInfo.ObjectOf(ident)
	v, _ := obj.(*types.Var)
	return v
}
