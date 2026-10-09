package einomcp

import (
	"encoding/json"
	"testing"

	"cyberstrike-ai/internal/agent"
	"cyberstrike-ai/internal/coverage"
)

func TestLedgerAlternativesSurviveModelToolSchemaConversion(t *testing.T) {
	info, err := toolInfoFromDefinition(agent.Tool{Type: "function", Function: agent.FunctionDefinition{
		Name: "upsert_project_fact", Parameters: map[string]interface{}{"type": "object", "properties": map[string]interface{}{"body_fields": coverage.LedgerBodySchema()}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := info.ParamsOneOf.ToJSONSchema()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(schema)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	body := fields["properties"].(map[string]interface{})["body_fields"].(map[string]interface{})
	alternatives, ok := body["properties"].(map[string]interface{})["alt_tried"].(map[string]interface{})
	if !ok {
		t.Fatal("model-facing tool schema lost alt_tried")
	}
	choices, ok := alternatives["anyOf"].([]interface{})
	if !ok || len(choices) != 2 || choices[0].(map[string]interface{})["type"] != "string" || choices[1].(map[string]interface{})["type"] != "array" {
		t.Fatalf("model-facing schema lost accepted text/array alternatives: %s", encoded)
	}
}
