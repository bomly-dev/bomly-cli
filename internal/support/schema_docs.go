package support

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// WriteCommandSchemaDocs writes markdown schema references for the supported command payloads.
func WriteCommandSchemaDocs(outputDir string) ([]string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", outputDir, err)
	}

	written := make([]string, 0, len(commandOutputSpecs()))
	for _, entry := range commandOutputSpecs() {
		markdown := GenerateSchemaReferenceMarkdown(entry.name, entry.typ)
		outputPath := filepath.Join(outputDir, entry.name+".md")
		if err := os.WriteFile(outputPath, []byte(markdown), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", outputPath, err)
		}
		written = append(written, outputPath)
	}

	return written, nil
}

// GenerateSchemaReferenceMarkdown produces markdown reference documentation for a root response type.
func GenerateSchemaReferenceMarkdown(command string, root reflect.Type) string {
	var builder strings.Builder
	title := strings.ToUpper(command[:1]) + command[1:]
	_, _ = fmt.Fprintf(&builder, "# Bomly %s JSON Schema Reference\n\n", title)
	_, _ = fmt.Fprintf(&builder, "Complete reference for the `bomly %s` JSON output.\n\n", command)

	visited := map[reflect.Type]bool{}
	collectStructTypes(root, visited)

	builder.WriteString("## Document\n\n")
	writeTypeTable(&builder, root)

	delete(visited, derefType(root))
	if len(visited) > 0 {
		types := make([]reflect.Type, 0, len(visited))
		for t := range visited {
			types = append(types, t)
		}
		sort.Slice(types, func(i, j int) bool {
			return types[i].Name() < types[j].Name()
		})

		builder.WriteString("## Types\n\n")
		for _, t := range types {
			_, _ = fmt.Fprintf(&builder, "### `%s`\n\n", t.Name())
			writeTypeTable(&builder, t)
		}
	}

	return builder.String()
}

func writeTypeTable(builder *strings.Builder, t reflect.Type) {
	t = derefType(t)
	if t.Kind() != reflect.Struct {
		return
	}

	fields := flatFields(t)
	if len(fields) == 0 {
		return
	}

	builder.WriteString("| Field | Type | Description |\n")
	builder.WriteString("|-------|------|-------------|\n")
	for _, field := range fields {
		jsonName, _ := parseJSONTag(field.Tag.Get("json"))
		if jsonName == "" {
			jsonName = field.Name
		}
		_, _ = fmt.Fprintf(builder, "| `%s` | %s | |\n", jsonName, jsonTypeName(field.Type))
	}
	builder.WriteString("\n")
}

func flatFields(t reflect.Type) []reflect.StructField {
	t = derefType(t)
	fields := make([]reflect.StructField, 0, t.NumField())
	for idx := 0; idx < t.NumField(); idx++ {
		field := t.Field(idx)
		if !field.IsExported() {
			continue
		}
		if field.Tag.Get("json") == "-" {
			continue
		}
		if field.Anonymous {
			fields = append(fields, flatFields(field.Type)...)
			continue
		}
		fields = append(fields, field)
	}
	return fields
}

func jsonTypeName(t reflect.Type) string {
	t = derefType(t)
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
		return fmt.Sprintf("Array<%s>", jsonTypeName(t.Elem()))
	case reflect.Map:
		return "`object`"
	case reflect.Struct:
		return fmt.Sprintf("[`%s`](#%s)", t.Name(), strings.ToLower(t.Name()))
	default:
		return "`unknown`"
	}
}

func collectStructTypes(t reflect.Type, visited map[reflect.Type]bool) {
	t = derefType(t)
	if t.Kind() != reflect.Struct {
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Pointer {
			collectStructTypes(t.Elem(), visited)
		}
		return
	}
	if visited[t] {
		return
	}
	visited[t] = true
	for idx := 0; idx < t.NumField(); idx++ {
		field := t.Field(idx)
		if !field.IsExported() {
			continue
		}
		if field.Tag.Get("json") == "-" {
			continue
		}
		collectStructTypes(field.Type, visited)
	}
}
