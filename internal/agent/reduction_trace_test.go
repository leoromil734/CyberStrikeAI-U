package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReductionReplayMetadataRoundTripDoesNotLeakToProvider(t *testing.T) {
	raw := `[{"role":"user","content":"u"},{"role":"assistant","tool_calls":[{"id":"one","type":"function","function":{"name":"exec","arguments":"{}"}}],"extra":{"_reduction_mw_processed":true,"unknown_private_field":"not-forwarded","cyberstrike_model_facing_trace_version":1}},{"role":"tool","tool_call_id":"one","content":"saved notice"}]`
	messages, err := ParseTraceMessages(raw)
	if err != nil || len(messages) != 3 || !messages[1].ReductionCleared {
		t.Fatalf("reduction marker lost while parsing trace: %+v %v", messages, err)
	}
	provider, err := json.Marshal(messages)
	if err != nil || strings.Contains(string(provider), "extra") || strings.Contains(string(provider), "_reduction_mw_processed") {
		t.Fatalf("runtime metadata leaked into provider payload: %s %v", provider, err)
	}
	persisted, err := MessagesToTraceJSON(messages)
	if err != nil || !strings.Contains(persisted, `"_reduction_mw_processed":true`) || strings.Contains(persisted, "unknown_private_field") {
		t.Fatalf("trace serialization lost allowlisted marker: %s %v", persisted, err)
	}
	restored, err := ParseTraceMessages(persisted)
	if err != nil || !restored[1].ReductionCleared || !restored[1].ModelFacingTrace {
		t.Fatalf("repeated trace round-trip lost replay metadata: %+v %v", restored, err)
	}
}

func TestReductionReplayMarkerRejectsWrongRolesAndTypes(t *testing.T) {
	for _, raw := range []string{
		`[{"role":"user","content":"u","extra":{"_reduction_mw_processed":true}}]`,
		`[{"role":"tool","content":"x","extra":{"_reduction_mw_processed":true}}]`,
		`[{"role":"assistant","content":"a","extra":{"_reduction_mw_processed":"true"}}]`,
		`[{"role":"assistant","content":"a","extra":{"_reduction_mw_processed":1}}]`,
		`[{"role":"assistant","content":"a"}]`,
	} {
		messages, err := ParseTraceMessages(raw)
		if err != nil || len(messages) != 1 || messages[0].ReductionCleared {
			t.Fatalf("untrusted/non-boolean replay marker accepted: %s %+v %v", raw, messages, err)
		}
	}
}
