package coverage

import (
	"strings"
	"testing"
)

func TestBlockedSourceAlternativesContract(t *testing.T) {
	key := "recon/source/run-a/oneforall/example"
	base := "assessment_id: run-a\ntool: oneforall\ntarget: example.test\nstatus: blocked\nraw: 0\nunique: 0\nincremental: 0\nerror: output parser unsupported\nevidence: execution:original\n"
	for _, suffix := range []string{
		"alt_tried: 'subfinder completed; execution:alternative retained'",
		"alt_tried: ['subfinder completed with 2 hosts; execution:alternative']",
		"alt_tried: 'No approved alternative is available under the current execution policy'",
	} {
		if err := ValidateLedgerFact(key, base+suffix); err != nil {
			t.Fatalf("documented alternative shape rejected: %s %v", suffix, err)
		}
	}
	for _, suffix := range []string{
		"", "alt_tried: ''", "alt_tried: none", "alt_tried: []", "alt_tried: ['']", "alt_tried: [none]",
		"alt_tried: [123]", "alt_tried: [{tool: subfinder}]", "alt_tried: [execution:real, none]",
	} {
		if err := ValidateLedgerFact(key, base+suffix); err == nil || !strings.Contains(err.Error(), "alt_tried") {
			t.Fatalf("invalid alternative accepted or incorrect diagnostic: %s %v", suffix, err)
		}
	}
	// covered sources do not require alternatives; this is not a global schema
	// requirement for endpoint, risk, phase or startup records.
	if err := ValidateLedgerFact(key, strings.Replace(base, "status: blocked", "status: covered", 1)); err != nil {
		t.Fatal(err)
	}
}

func TestLedgerSchemaAdvertisesBlockedSourceAlternatives(t *testing.T) {
	schema := LedgerBodySchema()
	fields := schema["properties"].(map[string]interface{})
	field, ok := fields["alt_tried"].(map[string]interface{})
	if !ok || !strings.Contains(field["description"].(string), "blocked") {
		t.Fatal("blocked requirement is absent from model-visible schema")
	}
	choices := field["anyOf"].([]interface{})
	if len(choices) != 2 || choices[0].(map[string]interface{})["type"] != "string" || choices[1].(map[string]interface{})["type"] != "array" {
		t.Fatalf("schema diverged from accepted alternative types: %+v", field)
	}
}
