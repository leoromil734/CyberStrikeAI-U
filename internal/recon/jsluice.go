package recon

import (
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
)

// JSLuice emits JSONL, not crawler responses. Source attribution/hash and the
// original match stay in the registered JSONL at Record.Location. Relative URLs
// remain relative: the JS asset's directory is NOT evidence of the runtime base.
// No host/service observations are synthesized from static string references.
func parseJSLuiceLine(obj map[string]json.RawMessage) ([]Record, error) {
	schema := str(obj, "schema")
	mode := str(obj, "mode")
	if schema != "" {
		if schema != "csai.jsluice.v1" || (mode != "urls" && mode != "secrets") {
			return nil, errFormat
		}
		hash, err := hex.DecodeString(str(obj, "source_sha256"))
		if err != nil || len(hash) != 32 {
			return nil, errFormat
		}
		if _, err := urlRecords(str(obj, "source_js"), "GET"); err != nil {
			return nil, errFormat
		}
	}
	if mode == "secrets" || str(obj, "kind") != "" {
		// A local filename alone cannot attribute a secret to a target. Native
		// secret output must be enriched by the offline adapter before import.
		if schema == "" || mode != "secrets" || str(obj, "kind") == "" {
			return nil, errFormat
		}
		rows, err := urlRecords(str(obj, "source_js"), "")
		if err != nil {
			return nil, err
		}
		r := rows[2]
		r.Kind = Candidate
		r.Method = ""
		r.TemplateID = "jsluice-secret:" + str(obj, "kind")
		r.Severity = "tentative"
		return []Record{r}, nil
	}
	raw := str(obj, "url")
	if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, " \t\r\n\x00") {
		return nil, errFormat
	}
	method := strings.ToUpper(str(obj, "method"))
	if method == "" {
		method = "UNKNOWN"
	}
	if len(method) > 16 || strings.ContainsAny(method, " \t\r\n") {
		return nil, errFormat
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return nil, errFormat
	}
	if u.IsAbs() {
		rows, err := urlRecords(raw, method)
		if err != nil {
			return nil, err
		}
		// Even an absolute API or .js reference is only an extracted endpoint.
		return []Record{rows[2]}, nil
	}
	return []Record{{Kind: Endpoint, RawURL: raw, RawPath: raw, Method: method}}, nil
}
