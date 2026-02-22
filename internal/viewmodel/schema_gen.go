//go:build ignore

// schema_gen generates JSON Schema files for each command output type.
//
//go:generate go run schema_gen.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/bomly/bomly-cli/internal/explain"
	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/viewmodel"
)

// schemaEntry maps a command name to its response type.
type schemaEntry struct {
	name string
	typ  reflect.Type
}

func main() {
	entries := []schemaEntry{
		{"scan", reflect.TypeOf(viewmodel.ScanResponse{})},
		{"diff", reflect.TypeOf(viewmodel.DiffResponse{})},
		{"explain", reflect.TypeOf(viewmodel.ExplainResponse{})},
	}

	outDir := filepath.Join("..", "..", "docs", "schemas")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	for _, e := range entries {
		schema := generateSchema(e.typ)
		schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
		schema["$id"] = fmt.Sprintf("https://bomly.dev/schemas/%s.json", e.name)
		schema["title"] = fmt.Sprintf("Bomly %s output", e.name)

		data, err := json.MarshalIndent(schema, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal %s: %v\n", e.name, err)
			os.Exit(1)
		}

		outPath := filepath.Join(outDir, e.name+".schema.json")
		if err := os.WriteFile(outPath, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
			os.Exit(1)
		}
		fmt.Printf("generated %s\n", outPath)
	}
}

// generateSchema produces a JSON-Schema-compatible map from a reflect.Type.
func generateSchema(t reflect.Type) map[string]any {
	return typeSchema(t, map[reflect.Type]bool{})
}

func typeSchema(t reflect.Type, visited map[reflect.Type]bool) map[string]any {
	// Dereference pointer.
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice:
		items := typeSchema(t.Elem(), visited)
		return map[string]any{"type": "array", "items": items}
	case reflect.Map:
		vals := typeSchema(t.Elem(), visited)
		return map[string]any{"type": "object", "additionalProperties": vals}
	case reflect.Struct:
		return structSchema(t, visited)
	default:
		return map[string]any{}
	}
}

func structSchema(t reflect.Type, visited map[reflect.Type]bool) map[string]any {
	if visited[t] {
		return map[string]any{"type": "object"}
	}
	visited[t] = true
	defer delete(visited, t)

	properties := map[string]any{}
	var required []string

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		name, opts := parseJSONTag(jsonTag)
		if name == "" {
			// Embedded struct — merge fields.
			if field.Anonymous {
				sub := typeSchema(field.Type, visited)
				if subProps, ok := sub["properties"].(map[string]any); ok {
					for k, v := range subProps {
						properties[k] = v
					}
				}
				if subReq, ok := sub["required"].([]string); ok {
					required = append(required, subReq...)
				}
				continue
			}
			name = field.Name
		}

		prop := typeSchema(field.Type, visited)
		properties[name] = prop

		if !opts.omitempty {
			required = append(required, name)
		}
	}

	schema := map[string]any{
		"type":       "object",
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

type jsonOpts struct {
	omitempty bool
}

func parseJSONTag(tag string) (string, jsonOpts) {
	if tag == "" {
		return "", jsonOpts{}
	}
	parts := strings.Split(tag, ",")
	name := parts[0]
	opts := jsonOpts{}
	for _, p := range parts[1:] {
		if p == "omitempty" {
			opts.omitempty = true
		}
	}
	return name, opts
}

// Ensure the types are referenced so the imports are used.
var (
	_ = output.PackageRef{}
	_ = explain.Path{}
	_ = viewmodel.ScanResponse{}
)
