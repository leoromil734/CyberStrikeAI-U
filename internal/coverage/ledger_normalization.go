package coverage

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NormalizeLedgerWrite handles unambiguous transport compatibility only at the
// write boundary. It never guesses counts, authorized scope or evidence, and
// never upgrades a tool's success status to a completed coverage result.
// Reads/Check remain strict, so old malformed records do not silently pass.
func NormalizeLedgerWrite(key, body string) (string, []string, error) {
	kind, namespace := ledgerKind(key), ledgerNamespaceID(key)
	if kind == "" || strings.TrimSpace(body) == "" {
		return body, nil, nil
	}
	fields, err := ParseLedgerBody(body)
	if err != nil {
		if namespace == "" {
			return body, nil, nil // retain free-form legacy facts
		}
		return "", nil, fmt.Errorf("%s: %w", key, err)
	}
	if namespace == "" && text(fields, "assessment_id") == "" {
		return body, nil, nil // a legacy source key is not a round identifier
	}
	changed := false
	var notes []string
	if _, supplied := fields["assessment_id"]; !supplied && namespace != "" {
		fields["assessment_id"] = namespace
		changed = true
		notes = append(notes, "assessment_id 已从版本化 fact_key 同步为 "+namespace+"；显式提供的 ID 仍须与 key 一致。")
	}
	if kind == "source" && text(fields, "status") == "success" {
		if original, supplied := fields["source_status"]; supplied && original != "success" {
			return "", nil, fmt.Errorf("%s: source_status conflicts with the supplied success status", key)
		}
		fields["source_status"], fields["status"] = "success", "active"
		if raw, prose := fields["raw"].(string); prose {
			if original, supplied := fields["raw_output"]; supplied && original != raw {
				return "", nil, fmt.Errorf("%s: raw_output conflicts with the supplied raw text", key)
			}
			fields["raw_output"] = raw
			delete(fields, "raw")
		}
		changed = true
		notes = append(notes, "来源已保存为 active（未完成），原工具 success 保存在 source_status，文本 raw 保存在 raw_output；补齐真实整数 raw/unique/incremental 和 evidence 后显式更新 status=covered。不会从 total/fetched 或文本猜计数、补造证据。")
	}
	if kind == "assessment" && text(fields, "status") == "active" {
		var missing []string
		for _, name := range []string{"scope_kind", "endpoint_count", "js_count", "risk_unit_count"} {
			if _, supplied := fields[name]; !supplied {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			notes = append(notes, "评估已保存为 active（未完成）启动记录；仍需补齐 "+strings.Join(missing, "/")+"。范围和库存计数未自动推断，覆盖门禁仍会阻断收尾；phases 列表不替代独立 recon/phase/{assessment_id}/{phase} 记录。")
		}
	}
	if !changed {
		return body, notes, nil
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return "", nil, fmt.Errorf("%s: cannot serialize normalized ledger body: %w", key, err)
	}
	if original := strings.TrimSpace(body); strings.HasPrefix(original, "{") {
		decoder := json.NewDecoder(strings.NewReader(original))
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err == nil {
			// ParseLedgerBody already validated any JSON tail as the host mirror.
			// Preserve its exact whitespace and incoming relationship text.
			return string(encoded) + original[decoder.InputOffset():], notes, nil
		}
	}
	return string(encoded), notes, nil
}
