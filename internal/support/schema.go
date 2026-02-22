package support

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
)

// WriteCommandSchemas writes JSON schema files for the supported command payloads.
func WriteCommandSchemas(outputDir string) ([]string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", outputDir, err)
	}

	written := make([]string, 0, len(commandOutputSpecs()))
	for _, entry := range commandOutputSpecs() {
		schema := GenerateJSONSchema(entry.typ)
		schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
		schema["$id"] = fmt.Sprintf("https://bomly.dev/schemas/%s.json", entry.name)
		schema["title"] = fmt.Sprintf("Bomly %s output", entry.name)

		data, err := json.MarshalIndent(schema, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal %s: %w", entry.name, err)
		}

		outputPath := filepath.Join(outputDir, entry.name+".schema.json")
		if err := os.WriteFile(outputPath, append(data, '\n'), 0o644); err != nil {
			return nil, fmt.Errorf("write %s: %w", outputPath, err)
		}
		written = append(written, outputPath)
	}

	return written, nil
}

// GenerateJSONSchema produces a JSON-Schema-compatible map from the given type.
func GenerateJSONSchema(t reflect.Type) map[string]any {
	return typeSchema(derefType(t), map[reflect.Type]bool{})
}

func typeSchema(t reflect.Type, visited map[reflect.Type]bool) map[string]any {
	t = derefType(t)

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
		return map[string]any{"type": "array", "items": typeSchema(t.Elem(), visited)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": typeSchema(t.Elem(), visited)}
	case reflect.Struct:
		return structSchema(t, visited)
	default:
		return map[string]any{}
	}
}

func structSchema(t reflect.Type, visited map[reflect.Type]bool) map[string]any {
	t = derefType(t)
	if visited[t] {
		return map[string]any{"type": "object"}
	}
	visited[t] = true
	defer delete(visited, t)

	properties := map[string]any{}
	var required []string

	for idx := 0; idx < t.NumField(); idx++ {
		field := t.Field(idx)
		if !field.IsExported() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		name, options := parseJSONTag(jsonTag)
		if name == "" {
			if field.Anonymous {
				child := typeSchema(field.Type, visited)
				if childProperties, ok := child["properties"].(map[string]any); ok {
					for key, value := range childProperties {
						properties[key] = value
					}
				}
				if childRequired, ok := child["required"].([]string); ok {
					required = append(required, childRequired...)
				}
				continue
			}
			name = field.Name
		}

		properties[name] = typeSchema(field.Type, visited)
		if !options.omitEmpty {
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
