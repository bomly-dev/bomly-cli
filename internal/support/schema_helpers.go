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
		if part == "omitempty" {
			options.omitEmpty = true
		}
	}
	return name, options
}

func derefType(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
}
