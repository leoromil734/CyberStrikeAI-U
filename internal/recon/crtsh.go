package recon

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"

	"cyberstrike-ai/internal/evidence"
)

var crtshLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var crtshID = regexp.MustCompile(`^[1-9][0-9]{0,31}$`)

// The adapter emits canonical ASCII IDNA names, never URLs, IPs or patterns.
// Suffix containment is a query filter, NOT an authorization decision.
func crtshDomain(host string) bool {
	if len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, label := range labels {
		if !crtshLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// csai.crtsh.v1 is a complete JSON original, not raw crt.sh JSON or a summary.
// All evidence (certificate IDs/times/names, query URLs, response hashes) stays
// in that original; a host's Location points at its complete certificates array.
// No service, IP, endpoint, liveness, scope or vulnerability is inferred from CT.
func parseCRTSh(reader io.Reader, c *collector) error {
	staged := &collector{limits: c.limits, result: ParsedOutput{State: evidence.Parsed}}
	err := parseCRTShEnvelope(reader, staged)
	if err == nil || errors.Is(err, errRecordLimit) {
		c.result = staged.result
	} else {
		// A malformed/contradictory envelope must not publish earlier guessed
		// rows, even if a valid-looking records array preceded the bad suffix.
		c.result = ParsedOutput{State: evidence.Invalid, Partial: true, Reason: "invalid_crtsh_envelope"}
	}
	return err
}

func crtshHeader(header map[string]json.RawMessage) (domain, status string, err error) {
	if str(header, "schema") != "csai.crtsh.v1" || str(header, "source") != "crt.sh" || str(header, "verification") != "unverified" {
		return "", "", errFormat
	}
	domain, status = str(header, "query_domain"), str(header, "status")
	if !crtshDomain(domain) || (status != "success" && status != "partial" && status != "error") {
		return "", "", errFormat
	}
	values := map[string]bool{}
	for _, field := range []string{"candidate_only", "coverage_complete", "partial", "truncated"} {
		var value *bool
		if json.Unmarshal(header[field], &value) != nil || value == nil {
			return "", "", errFormat
		}
		values[field] = *value
	}
	if !values["candidate_only"] || values["coverage_complete"] || (values["truncated"] && !values["partial"]) || values["partial"] != (status != "success") {
		return "", "", errFormat
	}
	return domain, status, nil
}

func parseCRTShEnvelope(reader io.Reader, c *collector) error {
	d := json.NewDecoder(reader)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errFormat
	}
	header := map[string]json.RawMessage{}
	seen := map[string]bool{}
	hosts := map[string]bool{}
	seenRecords := false
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return errFormat
		}
		key, ok := token.(string)
		if !ok || len(key) > 128 || seen[key] || len(seen) >= 64 {
			return errFormat
		}
		seen[key] = true
		if key != "records" {
			start := d.InputOffset()
			switch key {
			case "schema", "source", "query_domain", "status", "candidate_only", "verification", "coverage_complete", "partial", "truncated":
				// Required metadata must precede records, as emitted by the
				// adapter. A later header cannot retroactively authorize rows.
				var raw json.RawMessage
				if seenRecords || d.Decode(&raw) != nil {
					return errFormat
				}
				header[key] = raw
			default:
				if err = skipJSON(d); err != nil {
					return errFormat
				}
			}
			if d.InputOffset()-start > int64(c.limits.MaxLineBytes) || d.InputOffset() > c.limits.MaxBytes {
				return errFormat
			}
			continue
		}
		domain, status, err := crtshHeader(header)
		if err != nil {
			return err
		}
		seenRecords = true
		// Partial describes missing/truncated query output, not whether CT can
		// prove exhaustive asset coverage. The envelope keeps coverage_complete
		// false and the processor keeps all certificate names candidate-only.
		c.result.Partial = status != "success"
		if status == "partial" {
			c.result.Reason = "crtsh_upstream_partial"
		}
		if string(header["truncated"]) == "true" {
			c.result.Reason = "crtsh_upstream_truncated"
		}
		if status == "error" {
			c.result.State = evidence.Invalid
			c.result.Reason = "crtsh_query_error"
		}
		token, err = d.Token()
		if err != nil || token != json.Delim('[') {
			return errFormat
		}
		for d.More() {
			if status == "error" {
				return errFormat
			}
			start := d.InputOffset()
			var raw json.RawMessage
			if err = d.Decode(&raw); err != nil {
				return errFormat
			}
			end := d.InputOffset()
			if end-start > int64(c.limits.MaxLineBytes) || end > c.limits.MaxBytes {
				return errFormat
			}
			r, err := crtshRecord(raw, domain)
			if err != nil {
				c.result.Stats.Rejected++
				c.result.Partial = true
				if c.result.Reason == "" {
					c.result.Reason = "crtsh_rejected_records"
				}
				continue
			}
			if hosts[r.Host] {
				continue
			}
			hosts[r.Host] = true
			// Decoder.InputOffset includes whitespace/comma before a row;
			// use raw's exact length to locate a standalone JSON object.
			if err = c.add([]Record{r}, Location{Offset: end - int64(len(raw)), Length: int64(len(raw))}); err != nil {
				return err
			}
		}
		if token, err = d.Token(); err != nil || token != json.Delim(']') {
			return errFormat
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') || !seenRecords {
		return errFormat
	}
	if _, err = d.Token(); err != io.EOF {
		return errFormat
	}
	return nil
}

func crtshRecord(raw []byte, domain string) (Record, error) {
	var row struct {
		Host          string `json:"host"`
		Source        string `json:"source"`
		CandidateOnly bool   `json:"candidate_only"`
		Verification  string `json:"verification"`
		Certificates  []struct {
			ID             string `json:"id"`
			URL            string `json:"url"`
			Name           string `json:"name"`
			EntryTimestamp string `json:"entry_timestamp"`
			NotBefore      string `json:"not_before"`
			NotAfter       string `json:"not_after"`
		} `json:"certificates"`
	}
	if !utf8.Valid(raw) || json.Unmarshal(raw, &row) != nil || !crtshDomain(row.Host) || row.Source != "crt.sh" || !row.CandidateOnly || row.Verification != "unverified" {
		return Record{}, errFormat
	}
	if row.Host != domain && !strings.HasSuffix(row.Host, "."+domain) {
		return Record{}, errFormat
	}
	if len(row.Certificates) == 0 || len(row.Certificates) > 64 {
		return Record{}, errFormat
	}
	for _, cert := range row.Certificates {
		if !crtshID.MatchString(cert.ID) || cert.URL != "https://crt.sh/?id="+cert.ID || strings.TrimSpace(cert.Name) == "" || len(cert.Name) > 4096 || strings.ContainsRune(cert.Name, 0) {
			return Record{}, errFormat
		}
		for _, stamp := range []string{cert.EntryTimestamp, cert.NotBefore, cert.NotAfter} {
			if len(stamp) > 64 || strings.ContainsAny(stamp, "\x00\r\n") {
				return Record{}, errFormat
			}
		}
	}
	return Record{Kind: Host, Host: row.Host, RawHost: row.Host}, nil
}
