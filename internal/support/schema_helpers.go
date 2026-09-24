package support

import (
	"reflect"
	"strings"
)

type jsonTagOptions struct {
	omitEmpty bool
}

func parseJSONTag(tag string) (string, jsonTagOptions) {
	if tag == "" {
		return "", jsonTagOptions{}
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	options := jsonTagOptions{}
	for _, part := range parts[1:] {
		// omitzero is what a struct-valued or time field declares to be
		// optional; encoding/json omits it the same way.
		if part == "omitempty" || part == "omitzero" {
			options.omitEmpty = true
		}
	}
	return name, options
}

func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}
