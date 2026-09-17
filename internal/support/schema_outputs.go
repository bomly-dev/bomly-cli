package support

import (
	"reflect"

	"github.com/bomly-dev/bomly-cli/internal/output"
)

type commandOutputSpec struct {
	name string
	typ  reflect.Type
}

func commandOutputSpecs() []commandOutputSpec {
	return []commandOutputSpec{
		{name: "scan", typ: reflect.TypeFor[output.ScanResponse]()},
		{name: "diff", typ: reflect.TypeFor[output.DiffResponse]()},
		{name: "explain", typ: reflect.TypeFor[output.ExplainResponse]()},
	}
}
