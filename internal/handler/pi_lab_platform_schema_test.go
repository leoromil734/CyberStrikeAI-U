package handler

import (
	"encoding/json"
	"reflect"
	"testing"

	"cyberstrike-ai/internal/mcp"
)

func TestPILabPlatformFileDefinitionsRequiredSchema(t *testing.T) {
	want := map[string][]string{
		"load_skill":      {"name"},
		"read_skill_file": {"name", "path"},
		"read_file":       {"path"},
		"write_file":      {"path", "content"},
		"list_files":      nil,
	}
	for _, definition := range piPlatformFileDefinitions() {
		t.Run(definition.Name, func(t *testing.T) {
			data, err := json.Marshal(definition.InputSchema)
			if err != nil {
				t.Fatal(err)
			}
			var schema map[string]interface{}
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatal(err)
			}
			expected, known := want[definition.Name]
			if !known {
				t.Fatal("missing schema expectation")
			}
			required, exists := schema["required"]
			if !exists {
				if len(expected) != 0 {
					t.Fatal("required properties omitted")
				}
				return
			}
			items, ok := required.([]interface{})
			if !ok || len(items) != len(expected) {
				t.Fatalf("required must be an array with expected properties: %s", data)
			}
			for i, item := range items {
				if item != expected[i] {
					t.Fatalf("required property changed: %s", data)
				}
			}
		})
	}
}

func TestPILabPlatformDefinitionNormalizesNullRequired(t *testing.T) {
	for _, tc := range []struct {
		name     string
		required interface{}
		want     string
	}{
		{"null", nil, `{"type":"object"}`},
		{"nil_strings", []string(nil), `{"type":"object"}`},
		{"nil_interfaces", []interface{}(nil), `{"type":"object"}`},
		{"empty", []string{}, `{"type":"object","required":[]}`},
		{"nonempty", []string{"value"}, `{"type":"object","required":["value"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := map[string]interface{}{"type": "object", "required": tc.required}
			input := map[string]interface{}{
				"type": "object", "required": tc.required,
				"properties": map[string]interface{}{
					"nested": node,
					"array":  map[string]interface{}{"type": "array", "items": node},
				},
				"allOf": []interface{}{node},
			}
			before, _ := json.Marshal(input)
			definition, err := piPlatformDefinition(mcp.Tool{Name: "fixture", InputSchema: input})
			if err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal(input)
			if string(before) != string(after) {
				t.Fatal("normalization mutated the registered MCP schema")
			}
			var expected map[string]interface{}
			if err := json.Unmarshal([]byte(tc.want), &expected); err != nil {
				t.Fatal(err)
			}
			schema := definition.InputSchema
			properties := schema["properties"].(map[string]interface{})
			for _, got := range []interface{}{properties["nested"], properties["array"].(map[string]interface{})["items"], schema["allOf"].([]interface{})[0]} {
				if !reflect.DeepEqual(got, expected) {
					t.Fatalf("nested required normalization: got %#v, want %#v", got, expected)
				}
			}
			delete(schema, "properties")
			delete(schema, "allOf")
			if !reflect.DeepEqual(schema, expected) {
				t.Fatalf("root required normalization: got %#v, want %#v", schema, expected)
			}
		})
	}
}
