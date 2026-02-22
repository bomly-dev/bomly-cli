//go:build ignore

// schema_docs_gen generates Markdown reference documentation for each command output type,
// similar to Syft's JSON Schema Reference format.
//
//go:generate go run schema_docs_gen.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/bomly/bomly-cli/internal/explain"
	"github.com/bomly/bomly-cli/internal/output"
	"github.com/bomly/bomly-cli/internal/viewmodel"
)

type docEntry struct {
	name string
	typ  reflect.Type
}

func main() {
	entries := []docEntry{
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
		md := generateMarkdown(e.name, e.typ)
		outPath := filepath.Join(outDir, e.name+".md")
		if err := os.WriteFile(outPath, []byte(md), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
			os.Exit(1)
		}
		fmt.Printf("generated %s\n", outPath)
	}
}

// generateMarkdown produces a full markdown reference for a root response type.
func generateMarkdown(command string, root reflect.Type) string {
	var sb strings.Builder
	title := strings.ToUpper(command[:1]) + command[1:]
	sb.WriteString(fmt.Sprintf("# Bomly %s JSON Schema Reference\n\n", title))
	sb.WriteString(fmt.Sprintf("Complete reference for the `bomly %s` JSON output.\n\n", command))

	// Collect all struct types reachable from the root.
	visited := map[reflect.Type]bool{}
	collectStructTypes(root, visited)

	// The root type is documented first as "Document".
	sb.WriteString("## Document\n\n")
	writeTypeTable(&sb, root)

	// Collect non-root types for the "Types" section.
	delete(visited, deref(root))
	if len(visited) > 0 {
		sorted := make([]reflect.Type, 0, len(visited))
		for t := range visited {
			sorted = append(sorted, t)
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i].Name() < sorted[j].Name()
		})

		sb.WriteString("## Types\n\n")
		for _, t := range sorted {
			sb.WriteString(fmt.Sprintf("### `%s`\n\n", t.Name()))
			writeTypeTable(&sb, t)
		}
	}

	return sb.String()
}

// writeTypeTable writes a markdown table describing all JSON fields of a struct type.
func writeTypeTable(sb *strings.Builder, t reflect.Type) {
	t = deref(t)
	if t.Kind() != reflect.Struct {
		return
	}

	fields := flatFields(t)
	if len(fields) == 0 {
		return
	}

	sb.WriteString("| Field | Type | Description |\n")
	sb.WriteString("|-------|------|-------------|\n")
	for _, f := range fields {
		jsonName, _ := parseJSONTag(f.Tag.Get("json"))
		if jsonName == "" {
			jsonName = f.Name
		}
		typeStr := jsonTypeName(f.Type)
		sb.WriteString(fmt.Sprintf("| `%s` | %s | |\n", jsonName, typeStr))
	}
	sb.WriteString("\n")
}

// flatFields returns all exported, JSON-visible fields of a struct type,
// flattening embedded (anonymous) structs.
func flatFields(t reflect.Type) []reflect.StructField {
	t = deref(t)
	var fields []reflect.StructField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if f.Anonymous {
			fields = append(fields, flatFields(f.Type)...)
			continue
		}
		fields = append(fields, f)
	}
	return fields
}

// jsonTypeName returns a human-readable type string for markdown display.
func jsonTypeName(t reflect.Type) string {
	t = deref(t)
	switch t.Kind() {
	case reflect.String:
		return "`string`"
	case reflect.Bool:
		return "`boolean`"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "`integer`"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "`integer`"
	case reflect.Float32, reflect.Float64:
		return "`number`"
	case reflect.Slice:
		elem := jsonTypeName(t.Elem())
		return fmt.Sprintf("Array<%s>", elem)
	case reflect.Map:
		return "`object`"
	case reflect.Struct:
		return fmt.Sprintf("[`%s`](#%s)", t.Name(), strings.ToLower(t.Name()))
	default:
		return "`unknown`"
	}
}

// collectStructTypes recursively finds all struct types reachable from t.
func collectStructTypes(t reflect.Type, visited map[reflect.Type]bool) {
	t = deref(t)
	if t.Kind() != reflect.Struct {
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Ptr {
			collectStructTypes(t.Elem(), visited)
		}
		return
	}
	if visited[t] {
		return
	}
	visited[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		if f.Tag.Get("json") == "-" {
			continue
		}
		collectStructTypes(f.Type, visited)
	}
}

func deref(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t
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
