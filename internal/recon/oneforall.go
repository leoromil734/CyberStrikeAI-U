package recon

import (
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"cyberstrike-ai/internal/evidence"
)

var errOneForAllValueLimit = errors.New("oneforall_record_byte_limit")

// OneForAll/tablib exports ordinary JSON arrays of objects, not JSONL. Also
// accept a single row or an explicit data/results array envelope. Never recurse
// through arbitrary log/metadata fields looking for URLs or host-like strings.
func parseOneForAllJSON(reader io.Reader, c *collector) error {
	staged := &collector{limits: c.limits, result: ParsedOutput{State: evidence.Parsed}}
	d := json.NewDecoder(reader)
	err := parseOneForAllDocument(d, staged)
	if err == nil {
		if _, endErr := d.Token(); endErr != io.EOF {
			err = errFormat
		}
	}
	if err == nil || errors.Is(err, errRecordLimit) || errors.Is(err, errOneForAllValueLimit) {
		c.result = staged.result
		if errors.Is(err, errOneForAllValueLimit) {
			c.result.Reason = "record_byte_limit"
		}
	} else {
		// A broken envelope (including a log suffix) is not a valid ordinary
		// JSON original, even when its prefix happens to contain valid rows.
		c.result = ParsedOutput{State: evidence.Invalid, Partial: true, Reason: "invalid_oneforall_json"}
	}
	return err
}

func parseOneForAllDocument(d *json.Decoder, c *collector) error {
	token, err := d.Token()
	if err != nil {
		return errFormat
	}
	switch token {
	case json.Delim('['):
		return parseOneForAllArray(d, c)
	case json.Delim('{'):
		start := d.InputOffset() - 1
		row := map[string]json.RawMessage{}
		seen := map[string]bool{}
		envelope := false
		for d.More() {
			token, err = d.Token()
			if err != nil {
				return errFormat
			}
			key, ok := token.(string)
			if !ok || len(key) > 128 || seen[key] || len(seen) >= 128 {
				return errFormat
			}
			seen[key] = true
			if key == "data" || key == "results" {
				if envelope {
					return errFormat
				}
				envelope = true
				if token, err = d.Token(); err != nil || token != json.Delim('[') {
					return errFormat
				}
				if err = parseOneForAllArray(d, c); err != nil {
					return err
				}
				continue
			}
			var raw json.RawMessage
			if err = d.Decode(&raw); err != nil || !utf8.Valid(raw) {
				return errFormat
			}
			if len(raw) > c.limits.MaxLineBytes || d.InputOffset() > c.limits.MaxBytes {
				return errOneForAllValueLimit
			}
			row[key] = raw
		}
		if token, err = d.Token(); err != nil || token != json.Delim('}') {
			return errFormat
		}
		if envelope {
			return nil
		}
		end := d.InputOffset()
		if end-start > int64(c.limits.MaxLineBytes) {
			return errOneForAllValueLimit
		}
		return addOneForAllRow(c, row, Location{Offset: start, Length: end - start})
	default:
		return errFormat
	}
}

// Decode one row at a time. The outer parser's LimitedReader caps total bytes;
// each row is additionally bounded and offsets refer to its exact original JSON.
func parseOneForAllArray(d *json.Decoder, c *collector) error {
	for d.More() {
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil || !utf8.Valid(raw) {
			return errFormat
		}
		end := d.InputOffset()
		if len(raw) > c.limits.MaxLineBytes || end > c.limits.MaxBytes {
			return errOneForAllValueLimit
		}
		row, err := decodeObject(raw)
		if err != nil {
			c.result.Stats.Rejected++
			continue
		}
		if err = addOneForAllRow(c, row, Location{Offset: end - int64(len(raw)), Length: int64(len(raw))}); err != nil {
			return err
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') {
		return errFormat
	}
	return nil
}

func addOneForAllRow(c *collector, row map[string]json.RawMessage, loc Location) error {
	host, err := hostRecord(str(row, "subdomain", "domain", "host"))
	if err != nil {
		c.result.Stats.Rejected++
		return nil
	}
	return c.add([]Record{host}, loc)
}
