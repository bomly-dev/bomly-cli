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
		{name: "scan", typ: reflect.TypeOf(output.ScanResponse{})},
		{name: "diff", typ: reflect.TypeOf(output.DiffResponse{})},
		{name: "explain", typ: reflect.TypeOf(output.ExplainResponse{})},
	}
}
